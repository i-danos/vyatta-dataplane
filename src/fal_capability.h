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
 * What each loaded backend can offload, what it calls itself, and which one
 * gets an object.
 *
 * Read a capability as a statement about a backend, never about the box. With
 * no backend loaded every capability is false and every limit is zero, while
 * the software data path goes on doing VXLAN, MPLS, ACLs, QoS and multicast
 * exactly as before. "fal_backend_can(i, FAL_CAP_VXLAN) == false" means that
 * backend will not offload VXLAN; it does not mean VXLAN is unavailable. The
 * accessor is named to carry that -- an earlier draft called it
 * fal_capability(), which reads as a question about the system.
 *
 * The answers are cached per backend. They are fetched once when the backend
 * is loaded, because a per-object query would put a dlsym'd call into the
 * programming path to answer a question that cannot change while the backend
 * is loaded.
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
	/*
	 * Also the "no particular capability" marker that op groups such as
	 * ports and the switch itself pass to fal_backend_select(), which
	 * answers with the first loaded backend.
	 */
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
 * Ask every loaded backend what it can do and remember the answers. Called
 * once the plugins are loaded and their handlers registered; safe to call with
 * none, which resets everything to the no-offload state.
 */
void fal_capability_refresh(void);

/* Can backend `idx` offload this? False for an index that is not loaded. */
bool fal_backend_can(unsigned int idx, enum fal_cap cap);

/* How many, or 0 for "declines to say". */
uint64_t fal_backend_limit(unsigned int idx, enum fal_cap_limit limit);

/*
 * What backend `idx` calls itself, never NULL.
 *
 * "sw-dataplane" for an index that is not loaded, which is the name pd_show
 * has always printed for the software lane, so the two agree rather than
 * inventing a second word for the same thing.
 */
const char *fal_backend_name(unsigned int idx);

/* Free-form offload feature list, or "" -- never NULL. */
const char *fal_backend_offload_features(unsigned int idx);

/*
 * Which backend should take an object needing this capability.
 *
 * Returns an index, or FAL_BACKEND_NONE when nothing loaded declares it --
 * which is the ordinary case and means the object stays in software. The
 * preference order is the order the backends appear in platform.conf, because
 * that is the only place an operator can express one.
 *
 * FAL_CAP_LAST asks for "any backend", and answers with the first loaded, so
 * that op groups with no natural capability behave exactly as they did when
 * only one backend could exist.
 */
#define FAL_BACKEND_NONE UINT_MAX
unsigned int fal_backend_select(enum fal_cap cap);

/* "fal capability show" */
int cmd_fal_capability(FILE *f, int argc, char **argv);

#endif /* FAL_CAPABILITY_H */
