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

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_json_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_intf_internal.h"

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
		"              \"key\": \"vrf:default/table:254/10.74.0.0/24\","
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
		"            { \"class\": \"qos-if\",     \"enumerable\": false,"
		"              \"reason\": \"no walker\" }"
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
		"            { \"key\": \"vrf:default/table:254/127.0.0.0/8\","
		"              \"dataplane_owned\": true },"
		"            { \"key\": \"vrf:default/table:254/255.255.255.255/32\","
		"              \"dataplane_owned\": true },"
		"            { \"key\": \"vrf:default/table:254/10.76.0.0/24\","
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
