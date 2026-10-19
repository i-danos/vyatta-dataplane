#!/usr/bin/env python3
"""Mutation check for the next-hop assertions in dp_test_fal_capability.c (A06).

Extracts the expected-JSON templates of dpa_route_object_carries_next_hops from
the C source, renders them with the data plane's real interface name, and
matches them against representative `dpa object show` output using a Python
port of dp_test_json_subset() (tests/whole_dp/src/dp_test_json_utils.c:
objects: every expected key must match; arrays: every expected element must
subset-match SOME actual element; strings: fnmatch in either direction).
Then it mutates the output -- wrong or missing gateway, wrong or missing
interface, wrong kind, dropped hop, dropped route -- and requires every
mutation to be REJECTED.

It does not run the data plane, does not use the real C matcher, and the
actual-output fixtures are hand-built in the recorded shape. See the report
for what that leaves unproven. Run:  python3 -I check_nexthop_assertions.py
"""
import ast
import copy
import fnmatch
import json
import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).with_name("src") / "dp_test_fal_capability.c"
REAL_IFNAME = "dpT10"          # what the data plane printed for test name dp1T0
TEST_IFNAME = "dp1T0"


def function_body(text, name):
    start = text.index(f"DP_START_TEST(fal_cap, {name})")
    return text[start:text.index("} DP_END_TEST;", start)]


def templates(body):
    """The C string-literal format strings passed to snprintf(json, ...)."""
    out = []
    for m in re.finditer(r'snprintf\(json, sizeof\(json\),\s*((?:"(?:[^"\\]|\\.)*"\s*)+),',
                         body):
        lits = re.findall(r'"(?:[^"\\]|\\.)*"', m.group(1))
        out.append("".join(ast.literal_eval(l) for l in lits))
    return out


def subset(exp, act):
    """Port of json_val_subset(): True if everything in exp is matched in act."""
    if exp is None:
        return True
    if act is None or type(exp) is not type(act) and not (
            isinstance(exp, (int, float)) and isinstance(act, (int, float))
            and not isinstance(exp, bool) and not isinstance(act, bool)):
        return False
    if isinstance(exp, dict):
        return all(k in act and subset(v, act[k]) for k, v in exp.items())
    if isinstance(exp, list):
        return all(any(subset(e, a) for a in act) for e in exp)
    if isinstance(exp, str):
        return fnmatch.fnmatchcase(act, exp) or fnmatch.fnmatchcase(exp, act)
    return exp == act


def route_obj(cls, key, hops):
    return {"class": cls, "key": key, "state": "full", "backend": "fal-test",
            "dataplane_owned": False, "nh_index": 20, "next_hops": hops}


def gw(via, ifname=REAL_IFNAME):
    return {"kind": "gateway", "via": via, "ifname": ifname, "dead": False, "backup": False}


def connected(ifname=REAL_IFNAME):
    return {"kind": "directly connected", "ifname": ifname, "dead": False, "backup": False}


# Recorded shape (assessment evidence, dataplane-full-test.log) for IPv4;
# the IPv6 object is the same shape built by hand; its key format comes from
# rt6_dpa_emit() in src/netinet6/route_v6.c (same layout as IPv4).
def actual_v4():
    return {"dpa_objects": {"objects": [
        route_obj("route", "vrf:default/table:254/10.77.0.0/24/scope:0", [gw("1.1.1.2")]),
        route_obj("route", "vrf:default/table:254/1.1.1.0/24/scope:253", [connected()]),
        route_obj("route", "vrf:default/table:254/127.0.0.0/8/scope:254",
                  [{"kind": "blackhole", "dead": False, "backup": False}]),
    ]}}


def actual_v6():
    return {"dpa_objects": {"objects": [
        route_obj("route6", "vrf:default/table:254/2010:77:77::/64/scope:0", [gw("1:1:1::2")]),
    ]}}


class Mutation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        text = SRC.read_text()
        cls.body = function_body(text, "dpa_route_object_carries_next_hops")
        t = templates(cls.body)
        assert len(t) == 2, f"expected the v4 and v6 templates, found {len(t)}"
        cls.v4_tpl, cls.v6_tpl = t

    def exp4(self, ifname=REAL_IFNAME):
        return json.loads(self.v4_tpl.replace("%s", ifname))

    def exp6(self, ifname=REAL_IFNAME):
        return json.loads(self.v6_tpl.replace("%s", ifname))

    V6_KEY = "vrf:default/table:254/2010:77:77::/64/scope:0"

    # -- source guards: the A06 defect was a hard-coded interface name
    def test_source_uses_the_real_interface_name(self):
        self.assertIn(f'dp_test_intf_real("{TEST_IFNAME}"', self.body)
        self.assertNotIn(f'\\"ifname\\": \\"{TEST_IFNAME}\\"', self.body)
        self.assertEqual(self.v4_tpl.count("%s"), 2)
        self.assertEqual(self.v6_tpl.count("%s"), 1)

    def test_hardcoded_test_name_would_fail_against_real_output(self):
        # this is the original A06 failure: expected dp1T0, actual dpT10
        self.assertFalse(subset(self.exp4(TEST_IFNAME), actual_v4()))
        self.assertFalse(subset(self.exp6(TEST_IFNAME), actual_v6()))

    # -- controls
    def test_unmutated_output_matches(self):
        self.assertTrue(subset(self.exp4(), actual_v4()))
        self.assertTrue(subset(self.exp6(), actual_v6()))

    def test_matcher_port_is_not_vacuous(self):
        self.assertFalse(subset({"a": 1}, {"a": 2}))
        self.assertFalse(subset({"a": 1}, {}))
        self.assertFalse(subset({"a": [1, 2]}, {"a": [1]}))
        self.assertTrue(subset({"a": [1]}, {"a": [3, 1], "b": 9}))
        self.assertFalse(subset({"a": True}, {"a": 1}))

    # -- mutations: every one must be rejected
    def mutate4(self, fn):
        a = actual_v4()
        fn(a["dpa_objects"]["objects"])
        return a

    def mutate6(self, fn):
        a = actual_v6()
        fn(a["dpa_objects"]["objects"])
        return a

    def test_v4_gateway_and_interface_mutations_are_rejected(self):
        cases = {
            "wrong gateway": lambda o: o[0]["next_hops"][0].update(via="1.1.1.3"),
            "missing gateway": lambda o: o[0]["next_hops"][0].pop("via"),
            "wrong interface": lambda o: o[0]["next_hops"][0].update(ifname="dpT11"),
            "missing interface": lambda o: o[0]["next_hops"][0].pop("ifname"),
            "wrong kind": lambda o: o[0]["next_hops"][0].update(kind="local"),
            "gateway hop dead": lambda o: o[0]["next_hops"][0].update(dead=True),
            "gateway hop backup": lambda o: o[0]["next_hops"][0].update(backup=True),
            "hops gone": lambda o: o[0].update(next_hops=[]),
            "next_hops key gone": lambda o: o[0].pop("next_hops"),
            "route gone": lambda o: o.pop(0),
            "connected wrong interface": lambda o: o[1]["next_hops"][0].update(ifname="dpT11"),
            "connected missing interface": lambda o: o[1]["next_hops"][0].pop("ifname"),
            "connected wrong kind": lambda o: o[1]["next_hops"][0].update(kind="gateway"),
            "connected route gone": lambda o: o.pop(1),
        }
        for name, fn in cases.items():
            with self.subTest(name):
                self.assertFalse(subset(self.exp4(), self.mutate4(fn)))

    def test_v6_gateway_and_interface_mutations_are_rejected(self):
        cases = {
            "wrong gateway": lambda o: o[0]["next_hops"][0].update(via="1:1:1::3"),
            "missing gateway": lambda o: o[0]["next_hops"][0].pop("via"),
            "wrong interface": lambda o: o[0]["next_hops"][0].update(ifname="dpT11"),
            "missing interface": lambda o: o[0]["next_hops"][0].pop("ifname"),
            "wrong kind": lambda o: o[0]["next_hops"][0].update(kind="directly connected"),
            "hops gone": lambda o: o[0].update(next_hops=[]),
            "wrong class": lambda o: o[0].update(**{"class": "route"}),
            "route gone": lambda o: o.pop(0),
        }
        for name, fn in cases.items():
            with self.subTest(name):
                self.assertFalse(subset(self.exp6(), self.mutate6(fn)))

    def test_hop_on_another_route_cannot_stand_in_for_missing_hop(self):
        # v4: the gateway hop moves to the connected route's object
        def move(o):
            o[1]["next_hops"].append(copy.deepcopy(o[0]["next_hops"][0]))
            o[0]["next_hops"] = []
        self.assertFalse(subset(self.exp4(), self.mutate4(move)))

    # -- known weaknesses of the assertion itself (documented, not hidden)
    def test_v6_expectation_pins_the_route_key(self):
        self.assertEqual(self.exp6()["dpa_objects"]["objects"][0]["key"], self.V6_KEY)

    def test_v6_gateway_on_a_wrong_prefix_vrf_table_or_scope_is_rejected(self):
        wrong = {
            "wrong prefix": "vrf:default/table:254/2001:db8::/32/scope:0",
            "wrong prefix length": "vrf:default/table:254/2010:77:77::/48/scope:0",
            "wrong vrf": "vrf:red/table:254/2010:77:77::/64/scope:0",
            "wrong table": "vrf:default/table:255/2010:77:77::/64/scope:0",
            "wrong scope": "vrf:default/table:254/2010:77:77::/64/scope:253",
            "IPv4-style key": "vrf:default/table:254/10.77.0.0/24/scope:0",
        }
        for name, key in wrong.items():
            with self.subTest(name):
                a = actual_v6()
                a["dpa_objects"]["objects"][0]["key"] = key
                self.assertFalse(subset(self.exp6(), a))

    def test_v6_gateway_hop_on_another_route6_object_is_rejected(self):
        # the right hop exists, but on a different prefix; the pinned route has none
        a = actual_v6()
        other = route_obj("route6", "vrf:default/table:254/2001:db8::/32/scope:0",
                          [gw("1:1:1::2")])
        a["dpa_objects"]["objects"][0]["next_hops"] = []
        a["dpa_objects"]["objects"].append(other)
        self.assertFalse(subset(self.exp6(), a))

    def test_known_gap_extra_hop_is_not_detected(self):
        """Subset matching: a second, unexpected hop does not fail the test."""
        a = actual_v4()
        a["dpa_objects"]["objects"][0]["next_hops"].append(gw("9.9.9.9"))
        self.assertTrue(subset(self.exp4(), a))


if __name__ == "__main__":
    unittest.main()
