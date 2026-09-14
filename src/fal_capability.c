/*
 * Copyright (c) 2026, i-danos.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fal.h"
#include "fal_capability.h"
#include "fal_plugin.h"
#include "json_writer.h"
#include "vplane_log.h"

/* The name the software lane has always been called in "pd show dataplane". */
#define SW_BACKEND_NAME "sw-dataplane"

static struct {
	bool can[FAL_CAP_LAST];
	uint64_t limit[FAL_CAP_LIMIT_LAST];
	const char *name;
	const char *offload_features;
} cap_cache = {
	.name = SW_BACKEND_NAME,
	.offload_features = "",
};

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
 * A backend is entitled to reject an attribute it has never heard of, and
 * fal_get_switch_attrs() reports one status for the whole list. Asking for
 * twelve at once and getting -EOPNOTSUPP says nothing about which eleven it
 * would have answered, so a backend that supports all but one would report as
 * supporting none. This runs once at plugin load.
 */
static bool query_bool(uint32_t attr_id)
{
	struct fal_attribute_t attr = { .id = attr_id };

	if (fal_get_switch_attrs(1, &attr) != 0)
		return false;

	return attr.value.booldata;
}

static uint64_t query_u64(uint32_t attr_id)
{
	struct fal_attribute_t attr = { .id = attr_id };

	if (fal_get_switch_attrs(1, &attr) != 0)
		return 0;

	return attr.value.u64;
}

static const char *query_str(uint32_t attr_id, const char *def)
{
	struct fal_attribute_t attr = { .id = attr_id };

	if (fal_get_switch_attrs(1, &attr) != 0)
		return def;

	if (!attr.value.ptr)
		return def;

	return attr.value.ptr;
}

void fal_capability_refresh(void)
{
	unsigned int i;

	/*
	 * Reset first. A plugin that unloads must leave no claim behind: a
	 * stale "can offload VXLAN" would be worse than never having asked,
	 * because the lie survives the thing that told it.
	 */
	memset(&cap_cache, 0, sizeof(cap_cache));
	cap_cache.name = SW_BACKEND_NAME;
	cap_cache.offload_features = "";

	if (!fal_plugins_present())
		return;

	for (i = 0; i < FAL_CAP_LAST; i++)
		cap_cache.can[i] = query_bool(cap_attr[i]);

	for (i = 0; i < FAL_CAP_LIMIT_LAST; i++)
		cap_cache.limit[i] = query_u64(limit_attr[i]);

	/*
	 * A backend that answers nothing else still gets a name, because an
	 * anonymous backend is exactly the state this work exists to end. It
	 * is not called SW_BACKEND_NAME, which belongs to the software lane.
	 */
	cap_cache.name = query_str(FAL_SWITCH_ATTR_BACKEND_NAME, "backend");
	cap_cache.offload_features =
		query_str(FAL_SWITCH_ATTR_OFFLOAD_FEATURES, "");

	RTE_LOG(INFO, DATAPLANE,
		"FAL backend \"%s\": hw_offload=%s features=[%s]\n",
		cap_cache.name,
		cap_cache.can[FAL_CAP_HW_OFFLOAD] ? "yes" : "no",
		cap_cache.offload_features);
}

bool fal_backend_can(enum fal_cap cap)
{
	if (cap >= FAL_CAP_LAST)
		return false;

	return cap_cache.can[cap];
}

uint64_t fal_backend_limit(enum fal_cap_limit limit)
{
	if (limit >= FAL_CAP_LIMIT_LAST)
		return 0;

	return cap_cache.limit[limit];
}

const char *fal_backend_name(void)
{
	return cap_cache.name;
}

const char *fal_backend_offload_features(void)
{
	return cap_cache.offload_features;
}

/*
 * "fal capability show"
 *
 * The point of having this at all is that a capability model nothing outside
 * the data plane can read cannot be tested from outside the data plane either,
 * and every verification in this tree drives the box from outside.
 */
int cmd_fal_capability(FILE *f, int argc, char **argv)
{
	json_writer_t *wr;
	unsigned int i;

	/*
	 * Reached as "fal capability show", after cmd_fal() has consumed the
	 * leading "fal": argv[0] is "capability" and argv[1] is "show".
	 */
	if (argc < 2 || strcmp(argv[1], "show") != 0)
		return -1;

	wr = jsonw_new(f);
	if (!wr)
		return -1;

	jsonw_name(wr, "fal_capability");
	jsonw_start_object(wr);

	jsonw_string_field(wr, "backend", fal_backend_name());
	/*
	 * Whether a backend is loaded at all, separate from what it can do.
	 * Without it, "every capability false" is ambiguous between no backend
	 * and a backend that offloads nothing -- which are different states
	 * and want different actions.
	 */
	jsonw_bool_field(wr, "backend_loaded", fal_plugins_present());
	jsonw_string_field(wr, "offload_features",
			   fal_backend_offload_features());

	jsonw_name(wr, "can");
	jsonw_start_object(wr);
	for (i = 0; i < FAL_CAP_LAST; i++)
		jsonw_bool_field(wr, cap_names[i], cap_cache.can[i]);
	jsonw_end_object(wr);

	jsonw_name(wr, "limits");
	jsonw_start_object(wr);
	for (i = 0; i < FAL_CAP_LIMIT_LAST; i++)
		jsonw_uint_field(wr, limit_names[i], cap_cache.limit[i]);
	jsonw_end_object(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}
