/*
 * Copyright (c) 2026, i-danos. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Does the backend capability model answer what the backend said?
 *
 * The whole point of the model is that something can ask what a backend
 * offloads *before* programming an object, rather than programming one and
 * reading PD_OBJ_STATE_NO_SUPPORT afterwards. That makes it testable without
 * hardware, which matters more here than usual: an offload defect's symptom is
 * "traffic still forwards", because the software path catches everything, so
 * reachability cannot distinguish a working backend from one that does nothing
 * at all. This asserts what the data plane *believes*, which is the only thing
 * that differs between those two states.
 *
 * fal_plugin_test.c declares a deliberately mixed capability set -- IPv4 yes
 * and IPv6 no, VXLAN yes and MPLS no -- because all-true and all-false are
 * both indistinguishable from a stub that ignores the attribute id. Every
 * assertion below checks both a true and a false in the same breath for that
 * reason.
 */

#include <rte_log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_json_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dpa_object.h"
#include "json_writer.h"

DP_DECL_TEST_SUITE(fal_capability_suite);

DP_DECL_TEST_CASE(fal_capability_suite, fal_cap, NULL, NULL);

/*
 * The plugin is loaded in this harness, so the cache must carry its answers
 * rather than the no-backend defaults.
 */
DP_START_TEST(fal_cap, backend_identity)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"backends_loaded\": 2,"
		"        \"backends\": ["
		"            { \"index\": 0, \"backend\": \"fal-test\","
		"              \"offload_features\": \"none,test-only\" },"
		"            { \"index\": 1, \"backend\": \"fal-test-b\","
		"              \"offload_features\": \"rss,tx-checksum\" }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * A mixed set, asserted as a set, for each backend separately.
 *
 * Checking only the true ones would pass against a backend that answers true
 * to everything, and checking only the false ones would pass against one that
 * answers false to everything -- and "false to everything" is exactly what a
 * broken attribute id mapping produces, because an unknown id returns an error
 * and the query then defaults to false.
 *
 * The two backends declare complementary sets, so the same capability name
 * carries opposite values in the two objects. A cache that filled every slot
 * from one backend's answers would be caught here and nowhere else.
 */
DP_START_TEST(fal_cap, mixed_feature_set)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"backends\": ["
		"            { \"index\": 0, \"can\": {"
		"                \"ipv4\": true,   \"ipv6\": false,"
		"                \"vrf\": false,   \"vlan\": true,"
		"                \"qinq\": false,  \"mpls\": false,"
		"                \"vxlan\": false, \"evpn\": false,"
		"                \"acl\": false,   \"qos\": true,"
		"                \"multicast\": false,"
		"                \"hw_offload\": false } },"
		"            { \"index\": 1, \"can\": {"
		"                \"ipv4\": false,  \"ipv6\": true,"
		"                \"vrf\": true,    \"vlan\": false,"
		"                \"qinq\": true,   \"mpls\": true,"
		"                \"vxlan\": true,  \"evpn\": true,"
		"                \"acl\": true,    \"qos\": false,"
		"                \"multicast\": true,"
		"                \"hw_offload\": true } }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * Scale limits, which travel a different union member from the booleans and so
 * can break independently, and differ between the two backends so that one
 * backend's answers cannot stand in for the other's.
 *
 * The values are deliberately not round: 65536 or 4096 would also be produced
 * by a truncation or a shift, while 65537 and 4099 would not survive either.
 */
DP_START_TEST(fal_cap, scale_limits)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"backends\": ["
		"            { \"index\": 0, \"limits\": {"
		"                \"max_routes\": 65537,"
		"                \"max_next_hops\": 4099,"
		"                \"max_acl_entries\": 1031,"
		"                \"max_tunnels\": 257 } },"
		"            { \"index\": 1, \"limits\": {"
		"                \"max_routes\": 131075,"
		"                \"max_next_hops\": 8195,"
		"                \"max_acl_entries\": 2053,"
		"                \"max_tunnels\": 521 } }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * Selection discriminates.
 *
 * This is the assertion the second backend exists for. Every capability where
 * fal-test-b wins, it wins *against* the preference order -- it is second in
 * platform.conf -- so "picked the right backend" cannot be confused with
 * "picked the first one". And every capability where fal-test wins is one
 * fal-test-b declines, so the reverse cannot be confused with "picked the last
 * one" either.
 */
DP_START_TEST(fal_cap, selection_discriminates)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"selection\": {"
		"            \"ipv4\": \"fal-test\","
		"            \"vlan\": \"fal-test\","
		"            \"qos\": \"fal-test\","
		"            \"ipv6\": \"fal-test-b\","
		"            \"vrf\": \"fal-test-b\","
		"            \"qinq\": \"fal-test-b\","
		"            \"mpls\": \"fal-test-b\","
		"            \"vxlan\": \"fal-test-b\","
		"            \"evpn\": \"fal-test-b\","
		"            \"acl\": \"fal-test-b\","
		"            \"multicast\": \"fal-test-b\","
		"            \"hw_offload\": \"fal-test-b\""
		"        }"
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * The backend's name reaches the per-object programming report.
 *
 * Before this, that report named two fixed lanes, "sw-dataplane" and the
 * literal "hw". An anonymous lane can say that something offloaded an object
 * but not which of several did, and "which" is the entire content of a backend
 * preference or an offload policy.
 */
DP_START_TEST(fal_cap, pd_show_names_the_backend)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"objects\": ["
		"        {"
		"            \"route\": ["
		"                { \"dp\": \"fal-test\" }"
		"            ]"
		"        }"
		"    ]"
		"}");
	dp_test_check_json_state("pd show dataplane route", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * A route records which backend holds it, and says so from outside.
 *
 * The test plugin declares ipv4 true and implements ip entry points, so
 * dispatch sends routes to it and the record should name it. This is the half
 * of the report a reconciliation loop needs and a backend preference is
 * expressed in: "programmed" and "programmed *where*" are different facts, and
 * until now the report could only carry the first.
 *
 * Asserted through "pd show dataplane route full" rather than by reading the
 * struct, because a field nothing outside the data plane can read cannot be
 * tested from outside it either.
 */
DP_START_TEST(fal_cap, route_records_its_backend)
{
	json_object *expected;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("10.73.0.0/24 nh 1.1.1.2 int:dp1T0");

	expected = dp_test_json_create(
		"{"
		"    \"objects\": ["
		"        { \"prefix\": \"10.73.0.0/24\","
		"          \"backend\": \"fal-test\" }"
		"    ]"
		"}");
	dp_test_check_json_state("pd show dataplane route full", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("10.73.0.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

/*
 * The v4/v6 wrinkle, discriminated.
 *
 * fal-test declares ipv4 true and ipv6 false; fal-test-b the opposite (see
 * the file header and backend_identity). v4 and v6 routes share one handler
 * struct (fal_ip_ops) and dispatch through the same op_type token ("ip"), so
 * before the capability used to pick a backend could differ per call, every
 * route -- v4 or v6 -- was checked against FAL_CAP_IPV4 alone. A v6 route
 * would then have matched fal-test, whose new_route happily accepts any
 * address family (it does not check), and recorded backend "fal-test" for an
 * object that backend never actually declared it could offload -- a wrong
 * answer reachability testing cannot catch, because the route still forwards
 * either way.
 *
 * fal-test-b deliberately implements no route entry points at all (see its
 * own file header: "any op it implemented would be a second reason a test
 * could pass"), so this cannot assert success the way route_records_its_backend
 * does for v4 -- there is no working v6 backend to succeed against. What it
 * can assert, and what actually distinguishes the fix from its absence, is
 * where the *unsuccessful* attempt landed: "dpa object show route6" is
 * unfiltered by state, so the object appears either way, recording which
 * backend was actually asked. Before the fix it would be "fal-test",
 * state "full" -- a real, wrongly-attributed success. After it, "sw-dataplane",
 * state "no_support" -- correctly asked of a backend that says no, not of the
 * one that would have said yes for the wrong reason.
 */
DP_START_TEST(fal_cap, route6_dispatches_by_its_own_capability)
{
	json_object *expected;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1:1:1::1/64");
	dp_test_netlink_add_route("2010:73:73::/64 nh 1:1:1::2 int:dp1T0");

	expected = dp_test_json_create(
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"class\": \"route6\","
		"              \"state\": \"no_support\","
		"              \"backend\": \"sw-dataplane\" }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("dpa object show route6", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("2010:73:73::/64 nh 1:1:1::2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1:1:1::1/64");

} DP_END_TEST;

/*
 * The uniform object view: one shape for every class, and a class list that
 * says which classes can be walked.
 *
 * "pd show dataplane" reports per class, in each class's own terms. That is
 * right for a person reading routes and wrong for anything comparing what is
 * programmed against what was asked for, which would have to know every
 * class's private shape and would learn nothing about a class it had not been
 * taught.
 */
DP_START_TEST(fal_cap, dpa_object_uniform_shape)
{
	json_object *expected;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("10.74.0.0/24 nh 1.1.1.2 int:dp1T0");

	expected = dp_test_json_create(
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"class\": \"route\","
		"              \"key\": \"vrf:default/table:254/10.74.0.0/24/scope:0\","
		"              \"state\": \"full\","
		"              \"backend\": \"fal-test\" }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("dpa object show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("10.74.0.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

/*
 * A class that cannot be walked says so, rather than reporting nothing.
 *
 * This is the assertion the class list exists for. Something reconciling would
 * read a class it cannot walk as a class with nothing in it, and would then be
 * confidently silent about every object in it -- the same shape as every other
 * check in this tree that could not fail: an absence and an emptiness that
 * look identical.
 */
DP_START_TEST(fal_cap, dpa_object_names_what_it_cannot_walk)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"dpa_objects\": {"
		"        \"classes\": ["
		"            { \"class\": \"route\",      \"enumerable\": true },"
		"            { \"class\": \"route6\",     \"enumerable\": true },"
		"            { \"class\": \"mroute\",     \"enumerable\": true },"
		"            { \"class\": \"mroute6\",    \"enumerable\": true },"
		"            { \"class\": \"mpls-route\", \"enumerable\": true },"
		"            { \"class\": \"vrf\",        \"enumerable\": true },"
		"            { \"class\": \"qos-if\",     \"enumerable\": true },"
		"            { \"class\": \"qos-vlan\",   \"enumerable\": true }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("dpa object show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * A class other than route enumerates in the same shape, and agrees with what
 * the backend declared.
 *
 * Six of the eight classes carry their backend in three different containers
 * -- a struct for routes, bitfields in the MPLS node, two named fields in the
 * multicast forwarding cache. Which one a class happens to use is exactly what
 * a uniform view exists to stop a reader having to know.
 *
 * The values tie the chain together end to end: fal_plugin_test declares
 * vrf=false, so dispatch sends no VRF ops to it, fal_vrf_create returns
 * -EOPNOTSUPP, the state is no_support rather than error, and the backend is
 * sw-dataplane. Any one of those four disagreeing with the others is a defect,
 * and asserting them together is what makes that visible.
 */
DP_START_TEST(fal_cap, dpa_object_vrf_same_shape)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"class\": \"vrf\","
		"              \"key\": \"vrf:default\","
		"              \"state\": \"no_support\","
		"              \"backend\": \"sw-dataplane\" }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("dpa object show vrf", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * The per-object pd view lists objects with no backend loaded.
 *
 * It used to be gated on fal_plugins_present(), so on a box with no FAL
 * backend -- which is every DANOS 2608 box -- "pd show dataplane route full"
 * answered with an empty list while "pd show dataplane route" counted seven.
 * Two views of the same data disagreeing, with nothing to say why.
 *
 * An empty list where there are objects is not a policy, it is a false
 * statement: a reader cannot tell "no objects in this state" from "no backend
 * loaded". This harness always has a plugin, which is why the unit tests never
 * saw it and a probe on a real box did.
 *
 * The assertion has to be about *content*, not about the request succeeding.
 * "the command returned JSON" was true the whole time it was wrong.
 */
DP_START_TEST(fal_cap, pd_subset_lists_objects)
{
	json_object *expected;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("10.75.0.0/24 nh 1.1.1.2 int:dp1T0");

	expected = dp_test_json_create(
		"{"
		"    \"objects\": ["
		"        { \"prefix\": \"10.75.0.0/24\" }"
		"    ]"
		"}");
	dp_test_check_json_state("pd show dataplane route full", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("10.75.0.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

/*
 * The object view says which objects the data plane made for itself.
 *
 * 127.0.0.0/8, 255.255.255.255/32 and the reject default are reserved routes:
 * they exist in the forwarding table and correctly have no counterpart
 * upstream. Something comparing the two sides has to tell them from objects
 * that went missing, or a reconciliation loop would try to repair 127.0.0.0/8
 * by asking zebra for a route zebra was never going to have.
 *
 * Asserted with a configured route in the same breath, because "everything is
 * owned" and "nothing is owned" are both indistinguishable from a field wired
 * to a constant.
 */
DP_START_TEST(fal_cap, dpa_object_marks_dataplane_owned)
{
	json_object *expected;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("10.76.0.0/24 nh 1.1.1.2 int:dp1T0");

	expected = dp_test_json_create(
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"key\": \"vrf:default/table:254/127.0.0.0/8/scope:254\","
		"              \"dataplane_owned\": true },"
		"            { \"key\": \"vrf:default/table:254/255.255.255.255/32/scope:254\","
		"              \"dataplane_owned\": true },"
		"            { \"key\": \"vrf:default/table:254/10.76.0.0/24/scope:0\","
		"              \"dataplane_owned\": false }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("dpa object show route", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("10.76.0.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

/*
 * One prefix, two objects, both visible.
 *
 * The reserved reject default sits at LPM_SCOPE_PAN_DIMENSIONAL and a real
 * default route sits at an ordinary scope. The LPM keys on (prefix, depth,
 * scope) and the object key did not carry the third, so these two collapsed
 * onto one key: eight objects arrived at a comparison as six, and the
 * arithmetic that followed looked entirely normal.
 *
 * Asserting both is the point. Asserting only the real one would pass equally
 * well against a view that had lost the reserved one, which is the state this
 * exists to prevent.
 */
DP_START_TEST(fal_cap, two_defaults_are_two_objects)
{
	json_object *expected;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("0.0.0.0/0 nh 1.1.1.2 int:dp1T0");

	expected = dp_test_json_create(
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"key\": \"vrf:default/table:254/0.0.0.0/0/scope:-1\","
		"              \"dataplane_owned\": true },"
		"            { \"key\": \"vrf:default/table:254/0.0.0.0/0/scope:0\","
		"              \"dataplane_owned\": false }"
		"        ]"
		"    }"
		"}");
	dp_test_check_json_state("dpa object show route", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("0.0.0.0/0 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

/*
 * A route object carries its next hops, not only its existence.
 *
 * The object view said which routes the data plane held and nothing about
 * where they went, so comparing it with zebra could show a route missing and
 * never a route present with the wrong (or dead) next hop. That is the kind of
 * disagreement a link fault produces, and the one the view could not have shown.
 *
 * Asserted for both families and for a gateway and a directly connected route in
 * the same run, because "every next hop has a via" and "no next hop has one" are
 * equally what a field wired to a constant looks like.
 */
DP_START_TEST(fal_cap, dpa_route_object_carries_next_hops)
{
	json_object *expected;
	char ifname[IFNAMSIZ];
	char json[1024];

	/* The data plane reports the real interface name, not the test's. */
	dp_test_intf_real("dp1T0", ifname);

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("10.77.0.0/24 nh 1.1.1.2 int:dp1T0");

	snprintf(json, sizeof(json),
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"key\": \"vrf:default/table:254/10.77.0.0/24/scope:0\","
		"              \"next_hops\": ["
		"                  { \"kind\": \"gateway\","
		"                    \"via\": \"1.1.1.2\","
		"                    \"ifname\": \"%s\","
		"                    \"dead\": false,"
		"                    \"backup\": false }"
		"              ] },"
		"            { \"key\": \"vrf:default/table:254/1.1.1.0/24/scope:253\","
		"              \"next_hops\": ["
		"                  { \"kind\": \"directly connected\","
		"                    \"ifname\": \"%s\" }"
		"              ] }"
		"        ]"
		"    }"
		"}", ifname, ifname);
	expected = dp_test_json_create("%s", json);
	dp_test_check_json_state("dpa object show route", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("10.77.0.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1:1:1::1/64");
	dp_test_netlink_add_route("2010:77:77::/64 nh 1:1:1::2 int:dp1T0");

	snprintf(json, sizeof(json),
		"{"
		"    \"dpa_objects\": {"
		"        \"objects\": ["
		"            { \"class\": \"route6\","
		"              \"key\": \"vrf:default/table:254/2010:77:77::/64/scope:0\","
		"              \"next_hops\": ["
		"                  { \"kind\": \"gateway\","
		"                    \"via\": \"1:1:1::2\","
		"                    \"ifname\": \"%s\" }"
		"              ] }"
		"        ]"
		"    }"
		"}", ifname);
	expected = dp_test_json_create("%s", json);
	dp_test_check_json_state("dpa object show route6", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

	dp_test_netlink_del_route("2010:77:77::/64 nh 1:1:1::2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1:1:1::1/64");

} DP_END_TEST;


/*
 * Capture what the data plane writes to its log while `fn`-style test code runs.
 *
 * DPDK's log stream is redirected to a temporary file and put back afterwards. The level is NOT touched: the suite runs at
 * the data plane's default level (-d1), and "the record is visible at the default level" is part of what is asserted.
 */
static FILE *log_capture_start(void)
{
	FILE *f = tmpfile();

	dp_test_fail_unless(f, "tmpfile() failed");
	rte_openlog_stream(f);
	return f;
}

static char *log_capture_stop(FILE *f)
{
	long n;
	char *buf;

	fflush(f);
	rte_openlog_stream(NULL);
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	rewind(f);
	buf = calloc(1, n + 1);
	dp_test_fail_unless(buf, "no memory for the captured log");
	dp_test_fail_unless(fread(buf, 1, n, f) == (size_t)n, "short read of the captured log");
	fclose(f);
	return buf;
}

static int count_of(const char *hay, const char *needle)
{
	int n = 0;

	for (; (hay = strstr(hay, needle)); hay += strlen(needle))
		n++;
	return n;
}

/*
 * The data plane says, in its own log, that it finished programming a route.
 *
 * Before this the only line on the path was the one written when the netlink message ARRIVED (RTM_NEWROUTE ..., before the
 * route is installed), and the only lines about the outcome were failures. Nothing could tell from the log that a delivery
 * had completed, so a reader had to poll `dpa object show route` and infer.
 *
 * What is asserted is the whole line, not that "something about the route was logged": class, op, vrf, table, prefix, scope,
 * the two states and the backend, and two timestamps that parse as numbers. fal-test answers "full", so state=full and
 * backend=fal-test come from the backend that was actually asked, and result=ok is the software lane's verdict.
 * Exactly one line carries this prefix, and its first word is "programmed", which no delivery line starts with.
 */
DP_START_TEST(fal_cap, route_programmed_is_logged_once_with_its_fields)
{
	static const char want[] =
		"ROUTE: programmed cls=route op=add vrf=1 table=254 prefix=10.75.0.0/24 scope=0 result=ok sw_state=full state=full backend=fal-test mono_ns=";
	unsigned long long mono = 0, wall = 0;
	char *log, *line, *eol;
	FILE *cap;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

	cap = log_capture_start();
	dp_test_netlink_add_route("10.75.0.0/24 nh 1.1.1.2 int:dp1T0");
	log = log_capture_stop(cap);

	line = strstr(log, want);
	dp_test_fail_unless(line, "no completion record for 10.75.0.0/24 in:\n%s", log);
	dp_test_fail_unless(sscanf(line + strlen(want), "%llu wall_ns=%llu", &mono, &wall) == 2 && mono > 0 && wall > 0,
			    "timestamps missing or not numbers: %.200s", line);
	eol = strchr(line, '\n');
	dp_test_fail_unless(eol && !memchr(line, '\r', eol - line), "the record is not one terminated line");
	dp_test_fail_unless(count_of(log, "prefix=10.75.0.0/24") == 1, "expected exactly one record for the prefix:\n%s", log);
	dp_test_fail_unless(!strstr(log, "RTM_NEWROUTE"), "the delivery word must not be part of the completion record");

	free(log);
	dp_test_netlink_del_route("10.75.0.0/24 nh 1.1.1.2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

/*
 * The two lanes are reported and neither is renamed for the other.
 *
 * fal-test-b implements no route entry points, so the forwarding backend answers no_support and the object's own state is
 * no_support on sw-dataplane (this is what `dpa object show route6` prints). The software lane still inserted the route:
 * sw_state=full, result=ok. A record that collapsed the two would have to call this route a failure or the backend a success.
 */
DP_START_TEST(fal_cap, route6_programmed_reports_both_lanes)
{
	static const char want[] =
		"ROUTE: programmed cls=route6 op=add vrf=1 table=254 prefix=2010:75:75::/64 scope=0 result=ok sw_state=full state=no_support backend=sw-dataplane mono_ns=";
	char *log;
	FILE *cap;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1:1:1::1/64");

	cap = log_capture_start();
	dp_test_netlink_add_route("2010:75:75::/64 nh 1:1:1::2 int:dp1T0");
	log = log_capture_stop(cap);

	dp_test_fail_unless(strstr(log, want), "no route6 completion record in:\n%s", log);
	dp_test_fail_unless(count_of(log, "prefix=2010:75:75::/64") == 1, "expected exactly one record:\n%s", log);

	free(log);
	dp_test_netlink_del_route("2010:75:75::/64 nh 1:1:1::2 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1:1:1::1/64");

} DP_END_TEST;

/*
 * A replace of an existing prefix is a different record from the add: op=update.
 */
DP_START_TEST(fal_cap, route_replace_is_logged_as_update)
{
	char *log;
	FILE *cap;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_route("10.76.0.0/24 nh 1.1.1.2 int:dp1T0");

	cap = log_capture_start();
	dp_test_netlink_replace_route("10.76.0.0/24 nh 1.1.1.3 int:dp1T0");
	log = log_capture_stop(cap);

	dp_test_fail_unless(strstr(log, "ROUTE: programmed cls=route op=update vrf=1 table=254 prefix=10.76.0.0/24 scope=0 result=ok sw_state=full state=full backend=fal-test mono_ns="),
			    "no op=update record for the replaced route in:\n%s", log);
	dp_test_fail_unless(!strstr(log, "op=add vrf=1 table=254 prefix=10.76.0.0/24"), "a replace must not look like an add:\n%s", log);

	free(log);
	dp_test_netlink_del_route("10.76.0.0/24 nh 1.1.1.3 int:dp1T0");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");

} DP_END_TEST;

static int null_reason_walker(json_writer_t *json, enum pd_obj_state subset)
{
	return 0;
}

/*
 * A class with no walker and no written reason used to crash the data plane.
 *
 * jsonw_string() dereferences its argument and `not_enumerable` was passed through unchecked, so the first class added to
 * dpa_classes[] without a reason would have killed the process the next time anyone ran `dpa object show`. The real table has
 * no such class, so the table is a parameter and this one has the three kinds of row: walkable, no walker with a reason, no
 * walker without. Reaching the assertions at all means it did not crash.
 */
DP_START_TEST(fal_cap, dpa_object_class_without_a_reason_does_not_crash)
{
	static const struct dpa_obj_class table[] = {
		{ "walkable", null_reason_walker, NULL },
		{ "later", NULL, "not built yet" },
		{ "mystery", NULL, NULL },
		{ NULL, NULL, NULL },
	};
	char *buf = NULL;
	size_t sz = 0;
	FILE *f = open_memstream(&buf, &sz);
	json_writer_t *wr;
	bool matched;

	dp_test_fail_unless(f, "open_memstream failed");
	wr = jsonw_new(f);
	jsonw_start_object(wr);
	matched = dpa_object_write_classes(wr, table, NULL);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	fclose(f);

	dp_test_fail_unless(matched, "no class matched an unfiltered request");
	dp_test_fail_unless(strstr(buf, "{\"class\":\"walkable\",\"enumerable\":true}"), "walkable class changed shape: %s", buf);
	dp_test_fail_unless(strstr(buf, "{\"class\":\"later\",\"enumerable\":false,\"reason\":\"not built yet\"}"), "written reason lost: %s", buf);
	dp_test_fail_unless(strstr(buf, "{\"class\":\"mystery\",\"enumerable\":false,\"reason\":\"no reason recorded\"}"), "missing reason not covered: %s", buf);
	free(buf);

	/* an unknown name still matches nothing, which is how the caller reports an error */
	buf = NULL; sz = 0;
	f = open_memstream(&buf, &sz);
	wr = jsonw_new(f);
	jsonw_start_object(wr);
	matched = dpa_object_write_classes(wr, table, "nosuchclass");
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	fclose(f);
	dp_test_fail_unless(!matched, "an unknown class name must match nothing");
	dp_test_fail_unless(strstr(buf, "\"classes\":[]"), "unknown class did not give an empty list: %s", buf);
	free(buf);

} DP_END_TEST;
