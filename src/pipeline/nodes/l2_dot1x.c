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
 * Two pieces of state, and keeping them apart is the whole design:
 *
 *   feature attached          the port is configured for 802.1X
 *   ifp->if_dot1x_authorized  it has authenticated
 *
 * An earlier version used attachment alone and was wrong: it could not express
 * "configured but not yet authenticated", which is the state the feature
 * exists to enforce. It also put authorisation on the configuration path,
 * where it does not belong.
 *
 * The split follows what each thing is. Attachment is configuration: it goes
 * through vplaned's store, so it survives a dataplane restart and a port
 * configured for 802.1X comes back configured. Authorisation is runtime and is
 * deliberately NOT stored -- after a restart the port must come back
 * unauthorised and authenticate again, rather than resume forwarding on the
 * strength of an authentication the new dataplane instance never saw. Failing
 * closed is the only safe direction here.
 *
 * A port with no 802.1X has no feature in its ether-lookup chain at all, so it
 * costs nothing -- not a branch, not a load -- on a path that runs per packet
 * per core. A configured port costs one bit test, from a cacheline the ingress
 * path already reads.
 *
 * Where it sits in the chain is deliberate. After the monitoring features, so
 * a capture or port mirror still sees the frames being dropped -- a port that
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
#include "protobuf.h"
#include "protobuf/Dot1xConfig.pb-c.h"
#include "urcu.h"
#include "vplane_log.h"

ALWAYS_INLINE unsigned int
dot1x_in_process(struct pl_packet *pkt, void *context __unused)
{
	struct ifnet *ifp = pkt->in_ifp;
	const struct rte_ether_hdr *eth;

	/* The common case on a working port: authenticated, forward. */
	if (likely(ifp->if_dot1x_authorized))
		return DOT1X_IN_ACCEPT;

	/* Authentication has to be able to happen on a blocked port. */
	eth = ethhdr(pkt->mbuf);
	if (eth->ether_type == htons(ETH_P_PAE))
		return DOT1X_IN_ACCEPT;

	if_incr_dropped(ifp);
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

/*
 * Configuration. Reaches the dataplane through vplaned's store, so it survives
 * a restart. Enabling always leaves the port unauthorised: fail closed.
 */
static int dot1x_enable(FILE *f, const char *ifname, bool enable)
{
	struct ifnet *ifp = dp_ifnet_byifname(ifname);

	if (!ifp) {
		fprintf(f, "unknown interface: %s\n", ifname);
		return -1;
	}

	if (enable) {
		ifp->if_dot1x_authorized = 0;
		memset(&ifp->if_dot1x_station, 0,
		       sizeof(ifp->if_dot1x_station));
		pl_node_add_feature_by_inst(&dot1x_ether_in_feat, ifp);
	} else {
		pl_node_remove_feature_by_inst(&dot1x_ether_in_feat, ifp);
		ifp->if_dot1x_authorized = 0;
		memset(&ifp->if_dot1x_station, 0,
		       sizeof(ifp->if_dot1x_station));
	}

	return 0;
}

/*
 * Runtime. Driven by whatever is watching the authenticator, and not stored:
 * a restart has to leave the port unauthorised.
 */
static int dot1x_authorize(FILE *f, const char *ifname, bool authorized,
			   const char *station)
{
	struct ifnet *ifp = dp_ifnet_byifname(ifname);
	struct rte_ether_addr mac;

	if (!ifp) {
		fprintf(f, "unknown interface: %s\n", ifname);
		return -1;
	}

	if (!pl_node_is_feature_enabled_by_inst(&dot1x_ether_in_feat, ifp)) {
		fprintf(f, "802.1X is not enabled on %s\n", ifname);
		return -1;
	}

	/*
	 * The station is optional. An authorise without one still authorises --
	 * refusing would make a port that authenticated fail to forward because
	 * of a reporting detail, which is the wrong trade. The address is then
	 * left all-zero and "dot1x show" omits it.
	 */
	memset(&ifp->if_dot1x_station, 0, sizeof(ifp->if_dot1x_station));
	if (authorized && station) {
		if (ether_aton_r(station, &mac))
			ifp->if_dot1x_station = mac;
		else
			fprintf(f, "ignoring malformed station address: %s\n",
				station);
	}

	ifp->if_dot1x_authorized = authorized ? 1 : 0;
	return 0;
}

static int dot1x_show(FILE *f, const char *ifname)
{
	struct ifnet *ifp = dp_ifnet_byifname(ifname);
	bool enabled;
	json_writer_t *wr;

	if (!ifp) {
		fprintf(f, "unknown interface: %s\n", ifname);
		return -1;
	}

	enabled = pl_node_is_feature_enabled_by_inst(&dot1x_ether_in_feat, ifp);

	wr = jsonw_new(f);
	if (!wr)
		return -1;

	jsonw_name(wr, "dot1x");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "interface", ifname);
	jsonw_bool_field(wr, "enabled", enabled);
	jsonw_bool_field(wr, "authorized",
			 enabled && ifp->if_dot1x_authorized);
	/* What the forwarding path actually does, so a reader need not
	 * derive it from the two flags above.
	 */
	jsonw_string_field(wr, "port_state",
			   !enabled ? "unconfigured" :
			   ifp->if_dot1x_authorized ? "forwarding" :
			   "blocked-except-eapol");
	/*
	 * Only while the port is authorised, and only if one was supplied.
	 * Emitting an all-zero address would read as a station that
	 * authenticated from 00:00:00:00:00:00.
	 */
	if (enabled && ifp->if_dot1x_authorized &&
	    !rte_is_zero_ether_addr(&ifp->if_dot1x_station)) {
		const uint8_t *a = ifp->if_dot1x_station.addr_bytes;
		char buf[18];

		/*
		 * Two digits per octet, written out here rather than with
		 * ether_ntoa_r(), which emits the shortest form and drops
		 * leading zeros: 52:54:00:01:09:01 comes back as 52:54:0:1:9:1.
		 * That still looks like an address, so it reads as correct, but
		 * the YANG type is types:mac-address and its pattern requires
		 * [0-9a-fA-F]{2} per octet -- configd rejected the state with
		 * "Does not match pattern" and the leaf never reached the
		 * model. ether_ntoa_r is fine for the log lines that use it
		 * elsewhere; this field is validated.
		 */
		snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			 a[0], a[1], a[2], a[3], a[4], a[5]);
		jsonw_string_field(wr, "authenticated_station", buf);
	}
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;
}

/*
 * Configuration arrives as a protobuf command, not as text.
 *
 * These are two registries and only one of them is reached from vplaned.
 * cmd_table in commands.c is the console registry, which is where the text
 * commands below live; configuration replayed from the store is dispatched by
 * topic, and a command registered only in cmd_table is an unknown topic there.
 *
 * That failure is worth knowing about: the store accepts anything, so the
 * component that sent it sees success, and the dataplane then rejects the topic
 * on every resync -- "unknown topic", resync aborts, RESET, reconnect, forever.
 * systemctl still reports the dataplane active and there is no core dump. One
 * bad entry takes a router out.
 *
 * dp_feature_register_string_cfg_handler() would register a text config handler
 * and its own header marks it deprecated in favour of protobuf, so this is the
 * protobuf one.
 */
static int cmd_dot1x_cfg(struct pb_msg *msg)
{
	Dot1xConfig *cfg = dot1x_config__unpack(NULL, msg->msg_len,
						(void *)msg->msg);
	struct ifnet *ifp;
	int ret = -1;

	if (!cfg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read dot1x protobuf command\n");
		return -1;
	}

	if (!cfg->has_cmd || !cfg->if_name) {
		RTE_LOG(ERR, DATAPLANE, "dot1x: incomplete command\n");
		goto out;
	}

	ifp = dp_ifnet_byifname(cfg->if_name);
	if (!ifp) {
		/* Replay can arrive before the interface exists. Reporting it
		 * rather than failing silently: the caller cannot see this and
		 * the port would simply never be configured.
		 */
		RTE_LOG(ERR, DATAPLANE, "dot1x: no interface %s\n",
			cfg->if_name);
		goto out;
	}

	switch (cfg->cmd) {
	case DOT1X_CONFIG__COMMAND_TYPE__ENABLE:
		/* Always unauthorised on enable, including on a replay after a
		 * dataplane restart. Fail closed.
		 */
		ifp->if_dot1x_authorized = 0;
		memset(&ifp->if_dot1x_station, 0,
		       sizeof(ifp->if_dot1x_station));
		pl_node_add_feature_by_inst(&dot1x_ether_in_feat, ifp);
		ret = 0;
		break;
	case DOT1X_CONFIG__COMMAND_TYPE__DISABLE:
		pl_node_remove_feature_by_inst(&dot1x_ether_in_feat, ifp);
		ifp->if_dot1x_authorized = 0;
		memset(&ifp->if_dot1x_station, 0,
		       sizeof(ifp->if_dot1x_station));
		ret = 0;
		break;
	default:
		RTE_LOG(ERR, DATAPLANE, "dot1x: unknown command %d\n",
			cfg->cmd);
		break;
	}

out:
	dot1x_config__free_unpacked(cfg, NULL);
	return ret;
}

PB_REGISTER_CMD(dot1x_cfg_cmd) = {
	.cmd = "vyatta:dot1x",
	.handler = cmd_dot1x_cfg,
};

/*
 * dot1x enable      <interface>   configure 802.1X; port starts unauthorised
 * dot1x disable     <interface>   remove it
 * dot1x authorize   <interface> [<station-mac>]  authentication succeeded
 * dot1x unauthorize <interface>   session ended or failed
 * dot1x show        <interface>
 */
int cmd_dot1x(FILE *f, int argc, char **argv)
{
	static const char usage[] =
		"usage: dot1x {enable|disable|unauthorize|show} <interface>\n"
		"       dot1x authorize <interface> [<station-mac>]\n";

	if (argc < 3 || argc > 4) {
		fprintf(f, "%s", usage);
		return -1;
	}

	if (argc == 4 && strcmp(argv[1], "authorize") != 0) {
		fprintf(f, "%s", usage);
		return -1;
	}

	if (strcmp(argv[1], "enable") == 0)
		return dot1x_enable(f, argv[2], true);
	if (strcmp(argv[1], "disable") == 0)
		return dot1x_enable(f, argv[2], false);
	if (strcmp(argv[1], "authorize") == 0)
		return dot1x_authorize(f, argv[2], true,
				       argc == 4 ? argv[3] : NULL);
	if (strcmp(argv[1], "unauthorize") == 0)
		return dot1x_authorize(f, argv[2], false, NULL);
	if (strcmp(argv[1], "show") == 0)
		return dot1x_show(f, argv[2]);

	fprintf(f, "%s", usage);
	return -1;
}
