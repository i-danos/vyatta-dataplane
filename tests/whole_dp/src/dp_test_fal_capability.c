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
