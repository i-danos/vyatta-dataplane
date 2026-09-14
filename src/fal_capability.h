/*
 * Copyright (c) 2026, i-danos.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef FAL_CAPABILITY_H
#define FAL_CAPABILITY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/*
 * What the loaded backend can offload, and what it calls itself.
 *
 * Read this as a statement about the backend, never about the box. With no
 * backend loaded every capability is false and every limit is zero, while the
 * software data path goes on doing VXLAN, MPLS, ACLs, QoS and multicast
 * exactly as before. "fal_backend_can(FAL_CAP_VXLAN) == false" means nothing
 * will offload VXLAN; it does not mean VXLAN is unavailable. The name of the
 * accessor carries that and is worth keeping: an earlier draft called it
 * fal_capability(), which reads as a question about the system.
 *
 * The answers are cached. They are fetched once when a plugin is loaded,
 * because a per-object query would put a dlsym'd call into the programming
 * path to answer a question whose answer cannot change while the backend is
 * loaded.
 */

enum fal_cap {
	FAL_CAP_IPV4,
	FAL_CAP_IPV6,
	FAL_CAP_VRF,
	FAL_CAP_VLAN,
	FAL_CAP_QINQ,
	FAL_CAP_MPLS,
	FAL_CAP_VXLAN,
	FAL_CAP_EVPN,
	FAL_CAP_ACL,
	FAL_CAP_QOS,
	FAL_CAP_MULTICAST,
	FAL_CAP_HW_OFFLOAD,
	FAL_CAP_LAST,
};

enum fal_cap_limit {
	FAL_CAP_LIMIT_ROUTES,
	FAL_CAP_LIMIT_NEXT_HOPS,
	FAL_CAP_LIMIT_ACL_ENTRIES,
	FAL_CAP_LIMIT_TUNNELS,
	FAL_CAP_LIMIT_LAST,
};

/*
 * Ask the backend what it can do and remember the answers. Called once the
 * plugin is loaded and its handlers are registered; safe to call with no
 * backend, which resets everything to the no-offload state.
 */
void fal_capability_refresh(void);

/* Can the loaded backend offload this? False when there is no backend. */
bool fal_backend_can(enum fal_cap cap);

/* How many, or 0 for "declines to say". */
uint64_t fal_backend_limit(enum fal_cap_limit limit);

/*
 * What the backend calls itself, never NULL.
 *
 * "sw-dataplane" when nothing is loaded, which is the name pd_show has always
 * printed for the software lane, so the two agree rather than inventing a
 * second word for the same thing.
 */
const char *fal_backend_name(void);

/* Free-form offload feature list, or "" -- never NULL. */
const char *fal_backend_offload_features(void);

/* "fal capability show" */
int cmd_fal_capability(FILE *f, int argc, char **argv);

#endif /* FAL_CAPABILITY_H */
