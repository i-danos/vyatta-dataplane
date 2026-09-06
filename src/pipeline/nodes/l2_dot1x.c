/*
 * l2_dot1x.c -- IEEE 802.1X port authorisation
 *
 * Copyright (c) 2026, i-danos.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Blocks a port that has not authenticated, letting only EAPOL through so that
 * it can.
 *
 * The state is the feature's own attachment rather than a flag somewhere:
 *
 *   attached  the port is unauthorised -- everything but EAPOL is dropped
 *   detached  the port is authorised, or 802.1X is not configured on it
 *
 * That choice is what keeps this free. An authorised port has no feature in its
 * ether-lookup chain at all, so it costs nothing -- not a branch, not a load --
 * which matters on a path that runs per packet per core. It is also already
 * observable: "vplsh -l -c 'ifconfig <if>'" lists what is attached under
 * ether_lookup_features, so the blocked state needs no new counter or field to
 * be visible.
 *
 * Where it sits in the chain is deliberate. After the monitoring features, so a
 * capture or port mirror still sees the frames being dropped -- a port that
 * blocks traffic invisibly is very hard to diagnose. Before vlan-modify-in and
 * bridge-in, so nothing is forwarded, bridged or cross-connected off an
 * unauthorised port.
 *
 * EAPOL is passed through rather than punted here. The punt happens further on
 * in ether_forward_process(), which sends ETH_P_PAE to l2-local; doing it in
 * both places would be two mechanisms for one behaviour.
 *
 * Drops are counted with if_incr_dropped(), which is ifi_idropped and appears
 * as rx_dropped in the interface JSON. A new counter would have needed new
 * plumbing to become visible and would say nothing this one does not.
 */

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <string.h>

#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "interface.h"
#include "json_writer.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "urcu.h"

ALWAYS_INLINE unsigned int
dot1x_in_process(struct pl_packet *pkt, void *context __unused)
{
	const struct rte_ether_hdr *eth = ethhdr(pkt->mbuf);

	/* Authentication has to be able to happen on a blocked port. */
	if (eth->ether_type == htons(ETH_P_PAE))
		return DOT1X_IN_ACCEPT;

	if_incr_dropped(pkt->in_ifp);
	return DOT1X_IN_DROP;
}

PL_REGISTER_NODE(dot1x_in_node) = {
	.name = "vyatta:dot1x-in",
	.type = PL_PROC,
	.handler = dot1x_in_process,
	.num_next = DOT1X_IN_NUM,
	.next = {
		[DOT1X_IN_ACCEPT] = "term-noop",
		[DOT1X_IN_DROP]   = "term-drop",
	}
};

PL_REGISTER_FEATURE(dot1x_ether_in_feat) = {
	.name = "vyatta:dot1x-ether-in",
	.node_name = "dot1x-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_DOT1X,
	.visit_after = "portmonitor-in",
};

static int dot1x_set(FILE *f, const char *ifname, bool block)
{
	struct ifnet *ifp = dp_ifnet_byifname(ifname);

	if (!ifp) {
		fprintf(f, "unknown interface: %s\n", ifname);
		return -1;
	}

	if (block)
		pl_node_add_feature_by_inst(&dot1x_ether_in_feat, ifp);
	else
		pl_node_remove_feature_by_inst(&dot1x_ether_in_feat, ifp);

	return 0;
}

static int dot1x_show(FILE *f, const char *ifname)
{
	struct ifnet *ifp = dp_ifnet_byifname(ifname);
	json_writer_t *wr;

	if (!ifp) {
		fprintf(f, "unknown interface: %s\n", ifname);
		return -1;
	}

	wr = jsonw_new(f);
	if (!wr)
		return -1;

	jsonw_name(wr, "dot1x");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "interface", ifname);
	jsonw_bool_field(wr, "blocked",
			 pl_node_is_feature_enabled_by_inst(
				 &dot1x_ether_in_feat, ifp));
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;
}

/*
 * dot1x block   <interface>   port is unauthorised: drop all but EAPOL
 * dot1x unblock <interface>   port is authorised: forward normally
 * dot1x show    <interface>
 */
int cmd_dot1x(FILE *f, int argc, char **argv)
{
	if (argc != 3) {
		fprintf(f, "usage: dot1x {block|unblock|show} <interface>\n");
		return -1;
	}

	if (strcmp(argv[1], "block") == 0)
		return dot1x_set(f, argv[2], true);
	if (strcmp(argv[1], "unblock") == 0)
		return dot1x_set(f, argv[2], false);
	if (strcmp(argv[1], "show") == 0)
		return dot1x_show(f, argv[2]);

	fprintf(f, "usage: dot1x {block|unblock|show} <interface>\n");
	return -1;
}
