/*-
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IF_ETHER_H
#define IF_ETHER_H

#include <stdint.h>

#include "vplane_debug.h"
#include "if_llatbl.h"

struct rte_ether_addr;
struct ifnet;
struct llentry;
struct ndmsg;
struct rte_timer;

enum cont_src_en;

/* Debugging messages */
#define LLADDR_DEBUG(format, args...)	\
	DP_DEBUG(ARP, DEBUG, LLADDR, format, ##args)

void lladdr_update(struct ifnet *ifp, struct llentry *la, uint8_t state,
		   const struct rte_ether_addr *enaddr, uint16_t secs, uint16_t flags);
void lladdr_timer(struct rte_timer *, void *arg);
void in6_lladdr_timer(struct rte_timer *tim, void *arg);
void lladdr_nl_event(int family, struct ifnet *ifp,
			    uint16_t type, const struct ndmsg *ndm,
			    const void *dst,
			    const struct rte_ether_addr *lladdr);
void lladdr_flush_all(enum cont_src_en cont_src);
void ll_addr_set(struct llentry *lle, const struct rte_ether_addr *eth);
/* Call this to link to routes when an lle transitions to VALID */
void llentry_routing_install(struct llentry *lle);
void kernel_mark_neigh_reachable(const struct sockaddr *addr, uint32_t ifindex);
void kernel_neigh_netlink_sock_init(void);

/*
 * The socket this file opens to talk to the kernel, for other callers that
 * need to tell the kernel something rather than open a second one. NULL if it
 * could not be opened; every caller has to cope with that, because the
 * dataplane forwards perfectly well without it.
 */
struct mnl_socket *kernel_netlink_sock(void);
void kernel_neigh_netlink_sock_close(void);
void lladdr_ulr_update(struct ifnet *ifp, struct in_addr *addr, const bool confirmed);
const char *lladdr_ntop(struct llentry *la);

#endif /* IF_ETHER_H */
