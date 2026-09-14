/*
 * Copyright (c) 2026, i-danos.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fal.h"
#include "fal_capability.h"
#include "fal_plugin.h"
#include "json_writer.h"
#include "util.h"
#include "vplane_log.h"

/* The name the software lane has always been called in "pd show dataplane". */
#define SW_BACKEND_NAME "sw-dataplane"

/*
 * Must match FAL_MAX_BACKENDS in fal.c, which is four because
 * pd_obj_state_and_flags reserves four bits for a backend index.
 */
#define CAP_MAX_BACKENDS 4

struct backend_caps {
	bool can[FAL_CAP_LAST];
	uint64_t limit[FAL_CAP_LIMIT_LAST];
	const char *name;
	const char *offload_features;
};

static struct backend_caps cap_cache[CAP_MAX_BACKENDS];

static const char *const cap_names[FAL_CAP_LAST] = {
	[FAL_CAP_IPV4]       = "ipv4",
	[FAL_CAP_IPV6]       = "ipv6",
	[FAL_CAP_VRF]        = "vrf",
	[FAL_CAP_VLAN]       = "vlan",
	[FAL_CAP_QINQ]       = "qinq",
	[FAL_CAP_MPLS]       = "mpls",
	[FAL_CAP_VXLAN]      = "vxlan",
	[FAL_CAP_EVPN]       = "evpn",
	[FAL_CAP_ACL]        = "acl",
	[FAL_CAP_QOS]        = "qos",
	[FAL_CAP_MULTICAST]  = "multicast",
	[FAL_CAP_HW_OFFLOAD] = "hw_offload",
};

static const uint32_t cap_attr[FAL_CAP_LAST] = {
	[FAL_CAP_IPV4]       = FAL_SWITCH_ATTR_CAP_IPV4,
	[FAL_CAP_IPV6]       = FAL_SWITCH_ATTR_CAP_IPV6,
	[FAL_CAP_VRF]        = FAL_SWITCH_ATTR_CAP_VRF,
	[FAL_CAP_VLAN]       = FAL_SWITCH_ATTR_CAP_VLAN,
	[FAL_CAP_QINQ]       = FAL_SWITCH_ATTR_CAP_QINQ,
	[FAL_CAP_MPLS]       = FAL_SWITCH_ATTR_CAP_MPLS,
	[FAL_CAP_VXLAN]      = FAL_SWITCH_ATTR_CAP_VXLAN,
	[FAL_CAP_EVPN]       = FAL_SWITCH_ATTR_CAP_EVPN,
	[FAL_CAP_ACL]        = FAL_SWITCH_ATTR_CAP_ACL,
	[FAL_CAP_QOS]        = FAL_SWITCH_ATTR_CAP_QOS,
	[FAL_CAP_MULTICAST]  = FAL_SWITCH_ATTR_CAP_MULTICAST,
	[FAL_CAP_HW_OFFLOAD] = FAL_SWITCH_ATTR_CAP_HW_OFFLOAD,
};

static const char *const limit_names[FAL_CAP_LIMIT_LAST] = {
	[FAL_CAP_LIMIT_ROUTES]      = "max_routes",
	[FAL_CAP_LIMIT_NEXT_HOPS]   = "max_next_hops",
	[FAL_CAP_LIMIT_ACL_ENTRIES] = "max_acl_entries",
	[FAL_CAP_LIMIT_TUNNELS]     = "max_tunnels",
};

static const uint32_t limit_attr[FAL_CAP_LIMIT_LAST] = {
	[FAL_CAP_LIMIT_ROUTES]      = FAL_SWITCH_ATTR_CAP_MAX_ROUTES,
	[FAL_CAP_LIMIT_NEXT_HOPS]   = FAL_SWITCH_ATTR_CAP_MAX_NEXT_HOPS,
	[FAL_CAP_LIMIT_ACL_ENTRIES] = FAL_SWITCH_ATTR_CAP_MAX_ACL_ENTRIES,
	[FAL_CAP_LIMIT_TUNNELS]     = FAL_SWITCH_ATTR_CAP_MAX_TUNNELS,
};

/*
 * One attribute per call rather than one call for all of them.
 *
 * fal_get_switch_attrs_backend() reports one status for the whole list, and a
 * backend is entitled to reject an id it has never heard of -- the handler
 * already in this tree returns -EINVAL for exactly that. Asking for twelve at
 * once and getting an error says nothing about which eleven it would have
 * answered, so a backend supporting all but one would report as supporting
 * none, which is indistinguishable from no backend at all. This runs once per
 * backend at load.
 */
static bool query_bool(unsigned int idx, uint32_t attr_id)
{
	struct fal_attribute_t attr = { .id = attr_id };

	if (fal_get_switch_attrs_backend(idx, 1, &attr) != 0)
		return false;

	return attr.value.booldata;
}

static uint64_t query_u64(unsigned int idx, uint32_t attr_id)
{
	struct fal_attribute_t attr = { .id = attr_id };

	if (fal_get_switch_attrs_backend(idx, 1, &attr) != 0)
		return 0;

	return attr.value.u64;
}

static const char *query_str(unsigned int idx, uint32_t attr_id,
			     const char *def)
{
	struct fal_attribute_t attr = { .id = attr_id };

	if (fal_get_switch_attrs_backend(idx, 1, &attr) != 0)
		return def;

	if (!attr.value.ptr)
		return def;

	return attr.value.ptr;
}

/*
 * A declared capability and an implemented op group are two separate claims by
 * the same backend, and until this nothing compared them.
 *
 * Declaring a capability false stops dispatch sending that group's ops to the
 * backend, so a backend that implements a group and declares it false has
 * written itself out of the path -- silently, and with the object landing in
 * software, which looks exactly like a backend that simply could not take it.
 * That happened while this was being written: the test plugin declared qos
 * false while implementing twenty-five QoS entry points and the QoS counters
 * read zero.
 *
 * Logged rather than refused. Neither direction is unsafe: ops that are not
 * advertised are simply not sent, and a group advertised but not implemented
 * gets NULL entry points and falls through to software. What is harmful is
 * either happening without anyone being told.
 */
static void cap_check_consistency(unsigned int b)
{
	static const struct {
		enum fal_cap cap;
		enum fal_op_group group;
	} pairs[] = {
		{ FAL_CAP_IPV4,      FAL_OP_GROUP_IP },
		{ FAL_CAP_MULTICAST, FAL_OP_GROUP_IPMC },
		{ FAL_CAP_ACL,       FAL_OP_GROUP_ACL },
		{ FAL_CAP_QOS,       FAL_OP_GROUP_QOS },
		{ FAL_CAP_MPLS,      FAL_OP_GROUP_MPLS },
		{ FAL_CAP_VXLAN,     FAL_OP_GROUP_TUN },
		{ FAL_CAP_VLAN,      FAL_OP_GROUP_VLAN },
		{ FAL_CAP_VRF,       FAL_OP_GROUP_VRF },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(pairs); i++) {
		bool declared = cap_cache[b].can[pairs[i].cap];
		bool implemented = fal_backend_implements(b, pairs[i].group);

		if (declared == implemented)
			continue;

		RTE_LOG(WARNING, DATAPLANE,
			"FAL backend \"%s\": declares %s=%s but %s entry points for it\n",
			cap_cache[b].name, cap_names[pairs[i].cap],
			declared ? "true" : "false",
			implemented ? "has" : "has no");
	}
}

void fal_capability_refresh(void)
{
	unsigned int b, i, n;

	/*
	 * Reset first. A backend that unloads must leave no claim behind: a
	 * stale "can offload VXLAN" would be worse than never having asked,
	 * because the lie survives the thing that told it.
	 */
	memset(cap_cache, 0, sizeof(cap_cache));
	for (b = 0; b < CAP_MAX_BACKENDS; b++) {
		cap_cache[b].name = SW_BACKEND_NAME;
		cap_cache[b].offload_features = "";
	}

	n = fal_backend_count();
	for (b = 0; b < n && b < CAP_MAX_BACKENDS; b++) {
		for (i = 0; i < FAL_CAP_LAST; i++)
			cap_cache[b].can[i] = query_bool(b, cap_attr[i]);

		for (i = 0; i < FAL_CAP_LIMIT_LAST; i++)
			cap_cache[b].limit[i] = query_u64(b, limit_attr[i]);

		/*
		 * A backend that answers nothing else still gets a name,
		 * because an anonymous backend is what this work exists to
		 * end. Not SW_BACKEND_NAME, which belongs to the software
		 * lane, and distinct per slot so that two silent backends do
		 * not both answer to the same word.
		 */
		cap_cache[b].name =
			query_str(b, FAL_SWITCH_ATTR_BACKEND_NAME, NULL);
		if (!cap_cache[b].name) {
			static char anon[CAP_MAX_BACKENDS][16];

			snprintf(anon[b], sizeof(anon[b]), "backend%u", b);
			cap_cache[b].name = anon[b];
		}
		cap_cache[b].offload_features =
			query_str(b, FAL_SWITCH_ATTR_OFFLOAD_FEATURES, "");

		RTE_LOG(INFO, DATAPLANE,
			"FAL backend %u \"%s\": hw_offload=%s features=[%s]\n",
			b, cap_cache[b].name,
			cap_cache[b].can[FAL_CAP_HW_OFFLOAD] ? "yes" : "no",
			cap_cache[b].offload_features);

		cap_check_consistency(b);
	}
}

bool fal_backend_can(unsigned int idx, enum fal_cap cap)
{
	if (idx >= fal_backend_count() || idx >= CAP_MAX_BACKENDS)
		return false;
	if (cap >= FAL_CAP_LAST)
		return false;

	return cap_cache[idx].can[cap];
}

uint64_t fal_backend_limit(unsigned int idx, enum fal_cap_limit limit)
{
	if (idx >= fal_backend_count() || idx >= CAP_MAX_BACKENDS)
		return 0;
	if (limit >= FAL_CAP_LIMIT_LAST)
		return 0;

	return cap_cache[idx].limit[limit];
}

const char *fal_backend_name(unsigned int idx)
{
	if (idx >= fal_backend_count() || idx >= CAP_MAX_BACKENDS)
		return SW_BACKEND_NAME;

	return cap_cache[idx].name;
}

const char *fal_backend_offload_features(unsigned int idx)
{
	if (idx >= fal_backend_count() || idx >= CAP_MAX_BACKENDS)
		return "";

	return cap_cache[idx].offload_features;
}

unsigned int fal_backend_select(enum fal_cap cap)
{
	unsigned int b, n = fal_backend_count();

	if (n == 0)
		return FAL_BACKEND_NONE;

	/*
	 * "Any backend" -- the op groups with no natural capability. The first
	 * loaded, which with one backend is the behaviour this dispatch had
	 * before there could be more than one.
	 */
	if (cap >= FAL_CAP_LAST)
		return 0;

	for (b = 0; b < n && b < CAP_MAX_BACKENDS; b++)
		if (cap_cache[b].can[cap])
			return b;

	/*
	 * Nothing declares it. Not an error and not a fallback to backend
	 * zero: handing an object to a backend that has said it cannot take it
	 * produces a failure the caller then records as PD_OBJ_STATE_ERROR,
	 * when the truth is PD_OBJ_STATE_NO_SUPPORT and the object belongs in
	 * software. The caller sees no handler and the software path keeps it.
	 */
	return FAL_BACKEND_NONE;
}

/*
 * "fal capability show"
 *
 * A capability model nothing outside the data plane can read cannot be tested
 * from outside the data plane either, and every verification in this tree
 * drives the box from outside.
 */
int cmd_fal_capability(FILE *f, int argc, char **argv)
{
	json_writer_t *wr;
	unsigned int b, i, n;

	/*
	 * Reached as "fal capability show", after cmd_fal() has consumed the
	 * leading "fal": argv[0] is "capability" and argv[1] is "show".
	 */
	if (argc < 2 || strcmp(argv[1], "show") != 0)
		return -1;

	wr = jsonw_new(f);
	if (!wr)
		return -1;

	n = fal_backend_count();

	jsonw_name(wr, "fal_capability");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "backends_loaded", n);

	jsonw_name(wr, "backends");
	jsonw_start_array(wr);
	for (b = 0; b < n && b < CAP_MAX_BACKENDS; b++) {
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "index", b);
		jsonw_string_field(wr, "backend", cap_cache[b].name);
		jsonw_string_field(wr, "offload_features",
				   cap_cache[b].offload_features);

		jsonw_name(wr, "can");
		jsonw_start_object(wr);
		for (i = 0; i < FAL_CAP_LAST; i++)
			jsonw_bool_field(wr, cap_names[i], cap_cache[b].can[i]);
		jsonw_end_object(wr);

		jsonw_name(wr, "limits");
		jsonw_start_object(wr);
		for (i = 0; i < FAL_CAP_LIMIT_LAST; i++)
			jsonw_uint_field(wr, limit_names[i],
					 cap_cache[b].limit[i]);
		jsonw_end_object(wr);

		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);

	/*
	 * Who would actually get an object needing each capability. This is
	 * the part worth showing: the per-backend tables above say what each
	 * one claims, and this says what the selection makes of those claims.
	 * Reading the claims and working out the winner by hand is exactly the
	 * step where an operator and the code can disagree without noticing.
	 */
	jsonw_name(wr, "selection");
	jsonw_start_object(wr);
	for (i = 0; i < FAL_CAP_LAST; i++) {
		unsigned int sel = fal_backend_select(i);

		jsonw_string_field(wr, cap_names[i],
				   sel == FAL_BACKEND_NONE ?
				   SW_BACKEND_NAME : cap_cache[sel].name);
	}
	jsonw_end_object(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}
