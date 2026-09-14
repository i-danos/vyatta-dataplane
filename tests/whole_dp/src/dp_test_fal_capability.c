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
		"        \"backend\": \"fal-test\","
		"        \"backend_loaded\": true,"
		"        \"offload_features\": \"none,test-only\""
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * A mixed set, asserted as a set. Checking only the true ones would pass
 * against a backend that answers true to everything, and checking only the
 * false ones would pass against one that answers false to everything -- and
 * "false to everything" is exactly what a broken attribute id mapping
 * produces, because an unknown id returns -EOPNOTSUPP and the query defaults
 * to false.
 */
DP_START_TEST(fal_cap, mixed_feature_set)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"can\": {"
		"            \"ipv4\": true,"
		"            \"ipv6\": false,"
		"            \"vrf\": true,"
		"            \"vlan\": true,"
		"            \"qinq\": false,"
		"            \"mpls\": false,"
		"            \"vxlan\": true,"
		"            \"evpn\": false,"
		"            \"acl\": true,"
		"            \"qos\": false,"
		"            \"multicast\": false"
		"        }"
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * A software backend is a legitimate backend, and the distinction between
 * "programmed somewhere else" and "programmed in hardware" is what an operator
 * reading offload counters needs. The test plugin offloads nothing, so it
 * declares hw_offload false while declaring five features true -- which is
 * only a contradiction if the two are conflated.
 */
DP_START_TEST(fal_cap, hw_offload_is_separate_from_features)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"can\": {"
		"            \"hw_offload\": false,"
		"            \"vxlan\": true"
		"        }"
		"    }"
		"}");
	dp_test_check_json_state("fal capability show", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);

} DP_END_TEST;

/*
 * Scale limits, which travel a different union member from the booleans and so
 * can break independently. The values are deliberately not round: 65536 or
 * 4096 would also be produced by a truncation or a shift, while 65537 and 4099
 * would not survive either.
 */
DP_START_TEST(fal_cap, scale_limits)
{
	json_object *expected;

	expected = dp_test_json_create(
		"{"
		"    \"fal_capability\": {"
		"        \"limits\": {"
		"            \"max_routes\": 65537,"
		"            \"max_next_hops\": 4099,"
		"            \"max_acl_entries\": 1031,"
		"            \"max_tunnels\": 257"
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
