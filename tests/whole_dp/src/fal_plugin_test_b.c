/*
 * Copyright (c) 2026, i-danos. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A second backend, so that selection can be shown to select.
 *
 * With one backend loaded, every selection answers "backend 0" whatever the
 * capability is, and a selection function that always returns the only
 * available answer cannot be observed to be wrong. Proving that
 * fal_backend_select() discriminates needs two backends whose declared
 * capabilities differ, and a second one that is *not* first in the preference
 * order -- otherwise "picked the right backend" and "picked the first backend"
 * are the same reading.
 *
 * So this declares the complement of fal_plugin_test's set: IPv6 where that
 * declares IPv4, MPLS where that declares VXLAN. It sits second in
 * platform.conf, which means every capability it wins, it wins against the
 * preference order rather than with it.
 *
 * It implements nothing else. A backend that registers only a switch handler
 * is legitimate -- each entry point is resolved by its own dlsym and the rest
 * stay NULL -- and keeping it to that is deliberate: this file exists to be
 * selected or not selected, and any op it implemented would be a second reason
 * a test could pass.
 */

#include <errno.h>
#include <fal_plugin.h>
#include <rte_log.h>
#include <stdint.h>

#include "compiler.h"

__FOR_EXPORT
int fal_plugin_init(void)
{
	return 0;
}

__FOR_EXPORT
int fal_plugin_get_switch_attribute(uint32_t attr_count,
				    struct fal_attribute_t *attr_list)
{
	uint32_t i;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		/*
		 * The complement of fal_plugin_test's set.
		 *
		 * This plugin implements no ops at all, so every capability it
		 * declares here is for an op group *neither* plugin implements
		 * -- dispatch sends those ops to a handler whose entry points
		 * are all NULL, the call is skipped, and the software path
		 * keeps the object exactly as it would with no backend. That
		 * keeps the declaration honest while still giving selection
		 * something to choose between.
		 */
		case FAL_SWITCH_ATTR_CAP_IPV6:
		case FAL_SWITCH_ATTR_CAP_VRF:
		case FAL_SWITCH_ATTR_CAP_QINQ:
		case FAL_SWITCH_ATTR_CAP_MPLS:
		case FAL_SWITCH_ATTR_CAP_VXLAN:
		case FAL_SWITCH_ATTR_CAP_EVPN:
		case FAL_SWITCH_ATTR_CAP_ACL:
		case FAL_SWITCH_ATTR_CAP_MULTICAST:
			attr_list[i].value.booldata = true;
			break;
		case FAL_SWITCH_ATTR_CAP_IPV4:
		case FAL_SWITCH_ATTR_CAP_VLAN:
		case FAL_SWITCH_ATTR_CAP_QOS:
			attr_list[i].value.booldata = false;
			break;
		/*
		 * True here and false in the other one. A software backend and
		 * a hardware backend loaded together is the case the whole
		 * design is for, and it is worth one of the two saying so.
		 */
		case FAL_SWITCH_ATTR_CAP_HW_OFFLOAD:
			attr_list[i].value.booldata = true;
			break;

		/* Distinct from the other backend's, and not round. */
		case FAL_SWITCH_ATTR_CAP_MAX_ROUTES:
			attr_list[i].value.u64 = 131075;
			break;
		case FAL_SWITCH_ATTR_CAP_MAX_NEXT_HOPS:
			attr_list[i].value.u64 = 8195;
			break;
		case FAL_SWITCH_ATTR_CAP_MAX_ACL_ENTRIES:
			attr_list[i].value.u64 = 2053;
			break;
		case FAL_SWITCH_ATTR_CAP_MAX_TUNNELS:
			attr_list[i].value.u64 = 521;
			break;

		case FAL_SWITCH_ATTR_BACKEND_NAME:
			attr_list[i].value.ptr = "fal-test-b";
			break;
		case FAL_SWITCH_ATTR_OFFLOAD_FEATURES:
			attr_list[i].value.ptr = "rss,tx-checksum";
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;
}
