/*
 *  Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 *  Copyright (c) 2011-2015 by Brocade Communications Systems, Inc.
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef COMPAT_H
#define COMPAT_H

#include <netinet/ip.h>

#define _LINUX_IP_H /* linux/ip.h conflicts with netinet/ip.h */
#include <linux/types.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <linux/netconf.h>
#include <linux/if_link.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/if_tun.h>
#include <linux/mpls.h>
#include <sys/socket.h>

#include <rte_bus.h>
#include <rte_bus_pci.h>

#ifndef RTE_DEV_TO_PCI
#define RTE_DEV_TO_PCI(ptr) container_of(ptr, struct rte_pci_device, device)
#endif
#ifndef IND_ATTACHED_MBUF
#define IND_ATTACHED_MBUF RTE_MBUF_F_INDIRECT
#endif
#include <rte_log.h>
#ifndef RTE_LOGTYPE_MBUF
#define RTE_LOGTYPE_MBUF RTE_LOGTYPE_USER1
#endif

/*
 * Debian trixie's linux-vyatta kernel headers already ship this
 * Vyatta extension (linux/if_tun.h) unconditionally, unguarded by
 * TUN_META_DEFINED -- detect it via TUN_META_FLAG_MARK (which it also
 * always defines) to avoid a struct-redefinition error. Only .flags,
 * .mark, .iif are ever used in this codebase (see shadow.c/
 * shadow_receive.c), so the kernel's struct (which lacks the unused
 * .oif field) is a safe drop-in.
 */
#if !defined(TUN_META_DEFINED) && !defined(TUN_META_FLAG_MARK)
#define TUN_META_DEFINED
struct tun_meta {
	uint32_t flags;
	uint32_t mark;
	uint32_t iif;
	uint32_t oif;
};
#ifndef TUN_META_FLAG_MARK
#define TUN_META_FLAG_MARK 0x01
#endif
#ifndef TUN_META_FLAG_IIF
#define TUN_META_FLAG_IIF 0x02
#endif
#endif

/* For PKT_RX_VLAN - rte_mbuf has an inline function that uses rte_memcpy */
#include <rte_memcpy.h>
#include <rte_mbuf.h>

#define VRF_NAME_SIZE   128

/* Brocade vrouter T2 Metadata */
#define NSH_MD_CLASS_BROCADE_VROUTER 0xf000

/* NSH defines as in kernel */
#define NSH_TLVC_UINT32 0

#define NSH_MD_TYPE_IFINDEX_IN   1
#define NSH_MD_TYPE_IFINDEX_OUT  2
#define NSH_MD_TYPE_ADDR_IPv4_NH 3
#define NSH_MD_TYPE_ADDR_IPv6_NH 4
#define NSH_MD_TYPE_MARK         5
#define NSH_MD_TYPE_MWID         6
#define NSH_MD_TYPE_VRF_ID       7

/* Lengths in 4 byte words */
#define NSH_MD_LEN_IFINDEX   1
#define NSH_MD_LEN_MARK      1
#define NSH_MD_LEN_ADDR_IPv4 1
#define NSH_MD_LEN_ADDR_IPv6 4
#define NSH_MD_LEN_VRF_ID    1

#ifndef ETH_P_LLDP
#define ETH_P_LLDP	0x88CC
#endif

#ifndef MAX_MP_SELECT_LABELS
/* Maximum number of labels to look ahead at when selecting a path of
 * a multipath route
 */
#define MAX_MP_SELECT_LABELS 4
#endif

typedef uint16_t portid_t;

/* DPDK 21.11+ / 24.11 compatibility macros */
#ifndef RTE_MBUF_F_RX_VLAN
#define RTE_MBUF_F_RX_VLAN (1ULL << 0)
#endif
#ifndef RTE_MBUF_F_RX_VLAN_STRIPPED
#define RTE_MBUF_F_RX_VLAN_STRIPPED (1ULL << 6)
#endif
#ifndef RTE_MBUF_F_TX_VLAN
#define RTE_MBUF_F_TX_VLAN (1ULL << 57)
#endif
#ifndef RTE_MBUF_F_TX_IPV4
#define RTE_MBUF_F_TX_IPV4 (1ULL << 55)
#endif
#ifndef RTE_MBUF_F_TX_IPV6
#define RTE_MBUF_F_TX_IPV6 (1ULL << 56)
#endif
#ifndef RTE_MBUF_F_TX_IP_CKSUM
#define RTE_MBUF_F_TX_IP_CKSUM (1ULL << 54)
#endif
#ifndef RTE_MBUF_F_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_UDP_CKSUM (1ULL << 52)
#endif
#ifndef RTE_MBUF_F_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_TCP_CKSUM (1ULL << 52)
#endif
#ifndef RTE_MBUF_F_TX_OUTER_IPV4
#define RTE_MBUF_F_TX_OUTER_IPV4 (1ULL << 59)
#endif
#ifndef RTE_MBUF_F_TX_OUTER_IPV6
#define RTE_MBUF_F_TX_OUTER_IPV6 (1ULL << 60)
#endif
#ifndef RTE_MBUF_F_TX_OUTER_IP_CKSUM
#define RTE_MBUF_F_TX_OUTER_IP_CKSUM (1ULL << 58)
#endif
#ifndef RTE_MBUF_F_RX_IP_CKSUM_MASK
#define RTE_MBUF_F_RX_IP_CKSUM_MASK ((1ULL << 4) | (1ULL << 7))
#endif
#ifndef RTE_MBUF_F_RX_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_IP_CKSUM_BAD (1ULL << 4)
#endif
#ifndef RTE_MBUF_F_RX_L4_CKSUM_MASK
#define RTE_MBUF_F_RX_L4_CKSUM_MASK ((1ULL << 3) | (1ULL << 11))
#endif
#ifndef RTE_MBUF_F_RX_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD (1ULL << 3)
#endif
#ifndef RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD (1ULL << 5)
#endif
#ifndef RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD (1ULL << 15)
#endif

#ifndef PKT_RX_VLAN_PKT
#define PKT_RX_VLAN_PKT RTE_MBUF_F_RX_VLAN
#endif
#ifndef PKT_RX_VLAN
#define PKT_RX_VLAN RTE_MBUF_F_RX_VLAN
#endif
#ifndef PKT_TX_VLAN_PKT
#define PKT_TX_VLAN_PKT RTE_MBUF_F_TX_VLAN
#endif
#ifndef PKT_TX_VLAN
#define PKT_TX_VLAN RTE_MBUF_F_TX_VLAN
#endif
#ifndef PKT_RX_VLAN_STRIPPED
#define PKT_RX_VLAN_STRIPPED RTE_MBUF_F_RX_VLAN_STRIPPED
#endif
#ifndef PKT_TX_IPV4
#define PKT_TX_IPV4 RTE_MBUF_F_TX_IPV4
#endif
#ifndef PKT_TX_IPV6
#define PKT_TX_IPV6 RTE_MBUF_F_TX_IPV6
#endif
#ifndef PKT_TX_IP_CKSUM
#define PKT_TX_IP_CKSUM RTE_MBUF_F_TX_IP_CKSUM
#endif
#ifndef PKT_TX_UDP_CKSUM
#define PKT_TX_UDP_CKSUM RTE_MBUF_F_TX_UDP_CKSUM
#endif
#ifndef PKT_TX_TCP_CKSUM
#define PKT_TX_TCP_CKSUM RTE_MBUF_F_TX_TCP_CKSUM
#endif
#ifndef PKT_TX_OUTER_IPV4
#define PKT_TX_OUTER_IPV4 RTE_MBUF_F_TX_OUTER_IPV4
#endif
#ifndef PKT_TX_OUTER_IPV6
#define PKT_TX_OUTER_IPV6 RTE_MBUF_F_TX_OUTER_IPV6
#endif
#ifndef PKT_TX_OUTER_IP_CKSUM
#define PKT_TX_OUTER_IP_CKSUM RTE_MBUF_F_TX_OUTER_IP_CKSUM
#endif
#ifndef PKT_RX_IP_CKSUM_MASK
#define PKT_RX_IP_CKSUM_MASK RTE_MBUF_F_RX_IP_CKSUM_MASK
#endif
#ifndef PKT_RX_IP_CKSUM_BAD
#define PKT_RX_IP_CKSUM_BAD RTE_MBUF_F_RX_IP_CKSUM_BAD
#endif
#ifndef PKT_RX_L4_CKSUM_MASK
#define PKT_RX_L4_CKSUM_MASK RTE_MBUF_F_RX_L4_CKSUM_MASK
#endif
#ifndef PKT_RX_L4_CKSUM_BAD
#define PKT_RX_L4_CKSUM_BAD RTE_MBUF_F_RX_L4_CKSUM_BAD
#endif
#ifndef PKT_RX_OUTER_IP_CKSUM_BAD
#define PKT_RX_OUTER_IP_CKSUM_BAD RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD
#endif
#ifndef PKT_RX_OUTER_L4_CKSUM_BAD
#define PKT_RX_OUTER_L4_CKSUM_BAD RTE_MBUF_F_RX_OUTER_L4_CKSUM_BAD
#endif

#ifndef rte_get_master_lcore
#define rte_get_master_lcore() rte_get_main_lcore()
#endif

/* Link status compatibility */
#ifndef ETH_LINK_UP
#define ETH_LINK_UP RTE_ETH_LINK_UP
#endif
#ifndef ETH_LINK_DOWN
#define ETH_LINK_DOWN RTE_ETH_LINK_DOWN
#endif
#ifndef ETH_SPEED_NUM_10G
#define ETH_SPEED_NUM_10G RTE_ETH_SPEED_NUM_10G
#endif
#ifndef ETH_LINK_FULL_DUPLEX
#define ETH_LINK_FULL_DUPLEX RTE_ETH_LINK_FULL_DUPLEX
#endif
#ifndef ETH_LINK_HALF_DUPLEX
#define ETH_LINK_HALF_DUPLEX RTE_ETH_LINK_HALF_DUPLEX
#endif
#ifndef ETH_LINK_AUTONEG
#define ETH_LINK_AUTONEG RTE_ETH_LINK_AUTONEG
#endif
#ifndef ETH_LINK_FIXED
#define ETH_LINK_FIXED RTE_ETH_LINK_FIXED
#endif
#ifndef ETH_SPEED_NUM_UNKNOWN
#define ETH_SPEED_NUM_UNKNOWN RTE_ETH_SPEED_NUM_UNKNOWN
#endif
#ifndef ETH_LINK_SPEED_AUTONEG
#define ETH_LINK_SPEED_AUTONEG RTE_ETH_LINK_SPEED_AUTONEG
#endif
#ifndef ETH_LINK_SPEED_FIXED
#define ETH_LINK_SPEED_FIXED RTE_ETH_LINK_SPEED_FIXED
#endif
#ifndef ETH_LINK_SPEED_10M_HD
#define ETH_LINK_SPEED_10M_HD RTE_ETH_LINK_SPEED_10M_HD
#endif
#ifndef ETH_LINK_SPEED_10M
#define ETH_LINK_SPEED_10M RTE_ETH_LINK_SPEED_10M
#endif
#ifndef ETH_LINK_SPEED_100M_HD
#define ETH_LINK_SPEED_100M_HD RTE_ETH_LINK_SPEED_100M_HD
#endif
#ifndef ETH_LINK_SPEED_100M
#define ETH_LINK_SPEED_100M RTE_ETH_LINK_SPEED_100M
#endif
#ifndef ETH_LINK_SPEED_1G
#define ETH_LINK_SPEED_1G RTE_ETH_LINK_SPEED_1G
#endif
#ifndef ETH_LINK_SPEED_2_5G
#define ETH_LINK_SPEED_2_5G RTE_ETH_LINK_SPEED_2_5G
#endif
#ifndef ETH_LINK_SPEED_5G
#define ETH_LINK_SPEED_5G RTE_ETH_LINK_SPEED_5G
#endif
#ifndef ETH_LINK_SPEED_10G
#define ETH_LINK_SPEED_10G RTE_ETH_LINK_SPEED_10G
#endif
#ifndef ETH_LINK_SPEED_20G
#define ETH_LINK_SPEED_20G RTE_ETH_LINK_SPEED_20G
#endif
#ifndef ETH_LINK_SPEED_25G
#define ETH_LINK_SPEED_25G RTE_ETH_LINK_SPEED_25G
#endif
#ifndef ETH_LINK_SPEED_40G
#define ETH_LINK_SPEED_40G RTE_ETH_LINK_SPEED_40G
#endif
#ifndef ETH_LINK_SPEED_50G
#define ETH_LINK_SPEED_50G RTE_ETH_LINK_SPEED_50G
#endif
#ifndef ETH_LINK_SPEED_56G
#define ETH_LINK_SPEED_56G RTE_ETH_LINK_SPEED_56G
#endif
#ifndef ETH_LINK_SPEED_100G
#define ETH_LINK_SPEED_100G RTE_ETH_LINK_SPEED_100G
#endif

/* VLAN compatibility flags */
#ifndef ETH_VLAN_TYPE_UNKNOWN
#define ETH_VLAN_TYPE_UNKNOWN RTE_ETH_VLAN_TYPE_UNKNOWN
#endif
#ifndef ETH_VLAN_TYPE_OUTER
#define ETH_VLAN_TYPE_OUTER RTE_ETH_VLAN_TYPE_OUTER
#endif
#ifndef ETH_VLAN_TYPE_INNER
#define ETH_VLAN_TYPE_INNER RTE_ETH_VLAN_TYPE_INNER
#endif
#ifndef ETH_VLAN_FILTER_OFFLOAD
#define ETH_VLAN_FILTER_OFFLOAD RTE_ETH_VLAN_FILTER_OFFLOAD
#endif

/* DPDK 22.11/24.11 bonding slave -> member renaming compatibility macros */
#define rte_eth_bond_slave_add rte_eth_bond_member_add
#define rte_eth_bond_slave_remove rte_eth_bond_member_remove
#define rte_eth_bond_slaves_get rte_eth_bond_members_get
#define rte_eth_bond_active_slaves_get rte_eth_bond_active_members_get
#define rte_eth_bond_8023ad_slave_info rte_eth_bond_8023ad_member_info

/* RTE_SCHED compatibility constants */
#ifndef RTE_SCHED_PIPE_PROFILES_PER_PORT
#define RTE_SCHED_PIPE_PROFILES_PER_PORT 256
#endif
#ifndef RTE_SCHED_TC_WRR_MASK
#define RTE_SCHED_TC_WRR_MASK RTE_SCHED_WRR_MASK
#endif
#ifndef ETH_SPEED_NUM_NONE
#define ETH_SPEED_NUM_NONE RTE_ETH_SPEED_NUM_NONE
#endif
#ifndef MAX_DSCP
#define MAX_DSCP 64
#endif
#ifndef MAX_PCP
#define MAX_PCP 8
#endif
#ifndef RTE_NUM_DSCP_MAPS
#define RTE_NUM_DSCP_MAPS 8
#endif
#define rte_sched_subport_stats64 rte_sched_subport_stats
#define rte_sched_subport_read_stats64 rte_sched_subport_read_stats
#define rte_sched_queue_stats64 rte_sched_queue_stats
#define rte_sched_queue_read_stats64 rte_sched_queue_read_stats
#ifndef rte_red_queue_num_maps
#define rte_red_queue_num_maps(port, qid) 1
#endif

#ifndef RTE_MAX_DSCP_MAPS
#define RTE_MAX_DSCP_MAPS 16
#endif
#ifndef RTE_LOGTYPE_SCHED
#define RTE_LOGTYPE_SCHED RTE_LOGTYPE_USER1
#endif
#ifndef RTE_LOGTYPE_PMD
#define RTE_LOGTYPE_PMD RTE_LOGTYPE_USER1
#endif
#ifndef RTE_LOGTYPE_KNI
#define RTE_LOGTYPE_KNI RTE_LOGTYPE_USER1
#endif
#ifndef RTE_LOGTYPE_CRYPTODEVEAL
#define RTE_LOGTYPE_CRYPTODEVEAL RTE_LOGTYPE_USER1
#endif
#ifndef DSCP_BITS
#define DSCP_BITS 6
#endif
#ifndef PCP_BITS
#define PCP_BITS 3
#endif
#ifndef RTE_SCHED_TC_BITS
#define RTE_SCHED_TC_BITS 2
#endif
#ifndef rte_red_set_scaling
#define rte_red_set_scaling(max_len) 0
#endif
#ifndef rte_sched_get_profile_for_pipe
#define rte_sched_get_profile_for_pipe(port, qid) 0
#endif
/*
 * DANOS's own scheduler geometry: four traffic classes of eight queues each,
 * which is what its configuration, its CLI and dp_test_qos_basic's 64-entry
 * DSCP map all assume. These were introduced with the DPDK 24 port and set to
 * two bits and four queues, which is neither DANOS's model nor DPDK's -- the
 * queue map byte could then only encode queues 0-3, and the show output
 * enumerated four where callers expected eight.
 *
 * DPDK's own geometry is separate and smaller: RTE_SCHED_QUEUES_PER_PIPE (16)
 * slots per pipe, all but the last traffic class holding a single queue. The
 * two do not fit, so qos_dpdk.c maps between them; see the note there. Use
 * QOS_QUEUES_PER_PIPE for anything sizing DANOS's own arrays and
 * RTE_SCHED_QUEUES_PER_PIPE only where DPDK's layout is meant.
 */
#ifndef RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS
#define RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS 8
#endif
#ifndef QOS_QUEUES_PER_PIPE
#define QOS_QUEUES_PER_PIPE \
	(((RTE_SCHED_TC_MASK) + 1) * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS)
#endif

#include <rte_cryptodev.h>
#include <rte_crypto_sym.h>

#ifndef SIZEOF_ID_STRUCT
#define SIZEOF_ID_STRUCT 1
#endif
#ifndef ndpi_finalize_initalization
#define ndpi_finalize_initalization ndpi_finalize_initialization
#endif

typedef uint32_t rpcprog_t;
typedef uint32_t rpcproc_t;
typedef uint32_t rpcvers_t;
typedef uint32_t rpcprot_t;
typedef uint32_t rpcport_t;

#include <gssrpc/rpc.h>
#include <gssrpc/pmap_prot.h>

#include <rte_acl.h>

struct rte_acl_rcu_config {
	int mode;
	uint32_t dq_size;
	uint32_t dq_trigger_reclaim_limit;
	uint32_t dq_max_reclaim_size;
	int thread_id;
	void *v;
};
#define RTE_ACL_QSBR_MODE_DQ 0

static inline int rte_acl_rcu_qsbr_add(struct rte_acl_ctx *ctx __attribute__((unused)), const struct rte_acl_rcu_config *cfg __attribute__((unused))) {
	return 0;
}
/*
 * rte_acl_del_rule() and rte_acl_copy_rules() used to be stubbed out here,
 * returning 0 without touching the context. Both are DANOS additions to its own
 * DPDK and Debian's does not have them, so the stubs made rule deletion and
 * trie merging report success while doing nothing: a deleted policy or firewall
 * rule stayed in the ACL context and kept matching, and a merge produced an
 * empty destination trie.
 *
 * npf_rte_acl.c now keeps its own copy of each trie's rules and does both
 * itself -- deletion by rebuilding the context from what remains, which is the
 * only way stock DPDK allows a rule to be removed. Nothing should call these
 * names again, so they are gone rather than left as a stub that compiles.
 */

#ifndef IFF_META_HDR
#define IFF_META_HDR 0x0004
#endif

#ifndef rte_crypto_aead_algorithm_strings
static const char * const rte_crypto_aead_algorithm_strings[] __attribute__((unused)) = {
	[RTE_CRYPTO_AEAD_AES_CCM] = "aes-ccm",
	[RTE_CRYPTO_AEAD_AES_GCM] = "aes-gcm",
	[RTE_CRYPTO_AEAD_CHACHA20_POLY1305] = "chacha20-poly1305",
};
#endif

#ifndef rte_crypto_cipher_algorithm_strings
static const char * const rte_crypto_cipher_algorithm_strings[] __attribute__((unused)) = {
	[RTE_CRYPTO_CIPHER_NULL] = "null",
	[RTE_CRYPTO_CIPHER_3DES_CBC] = "3des-cbc",
	[RTE_CRYPTO_CIPHER_AES_CBC] = "aes-cbc",
	[RTE_CRYPTO_CIPHER_AES_CTR] = "aes-ctr",
};
#endif

#ifndef rte_crypto_auth_algorithm_strings
static const char * const rte_crypto_auth_algorithm_strings[] __attribute__((unused)) = {
	[RTE_CRYPTO_AUTH_NULL] = "null",
	[RTE_CRYPTO_AUTH_SHA1_HMAC] = "sha1-hmac",
	[RTE_CRYPTO_AUTH_SHA256_HMAC] = "sha256-hmac",
	[RTE_CRYPTO_AUTH_SHA384_HMAC] = "sha384-hmac",
	[RTE_CRYPTO_AUTH_SHA512_HMAC] = "sha512-hmac",
	[RTE_CRYPTO_AUTH_AES_GMAC] = "aes-gmac",
};
#endif
#ifndef RTE_SCHED_WRR_BITS
#define RTE_SCHED_WRR_BITS 3
#endif
#ifndef RTE_SCHED_TC_MASK
#define RTE_SCHED_TC_MASK ((1 << RTE_SCHED_TC_BITS) - 1)
#endif
#ifndef RTE_SCHED_WRR_MASK
#define RTE_SCHED_WRR_MASK ((1 << RTE_SCHED_WRR_BITS) - 1)
#endif
#ifndef RTE_SCHED_TC_WRR_BITS
#define RTE_SCHED_TC_WRR_BITS (RTE_SCHED_TC_BITS + RTE_SCHED_WRR_BITS)
#endif

/* Offload flags compatibility */
#ifndef DEV_RX_OFFLOAD_VLAN_STRIP
#define DEV_RX_OFFLOAD_VLAN_STRIP RTE_ETH_RX_OFFLOAD_VLAN_STRIP
#endif
#ifndef DEV_RX_OFFLOAD_IPV4_CKSUM
#define DEV_RX_OFFLOAD_IPV4_CKSUM RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#endif
#ifndef DEV_RX_OFFLOAD_UDP_CKSUM
#define DEV_RX_OFFLOAD_UDP_CKSUM RTE_ETH_RX_OFFLOAD_UDP_CKSUM
#endif
#ifndef DEV_RX_OFFLOAD_TCP_CKSUM
#define DEV_RX_OFFLOAD_TCP_CKSUM RTE_ETH_RX_OFFLOAD_TCP_CKSUM
#endif
#ifndef DEV_RX_OFFLOAD_TCP_LRO
#define DEV_RX_OFFLOAD_TCP_LRO RTE_ETH_RX_OFFLOAD_TCP_LRO
#endif
#ifndef DEV_RX_OFFLOAD_QINQ_STRIP
#define DEV_RX_OFFLOAD_QINQ_STRIP RTE_ETH_RX_OFFLOAD_QINQ_STRIP
#endif
#ifndef DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM
#define DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM
#endif
#ifndef DEV_RX_OFFLOAD_MACSEC_STRIP
#define DEV_RX_OFFLOAD_MACSEC_STRIP RTE_ETH_RX_OFFLOAD_MACSEC_STRIP
#endif
#ifndef DEV_RX_OFFLOAD_VLAN_FILTER
#define DEV_RX_OFFLOAD_VLAN_FILTER RTE_ETH_RX_OFFLOAD_VLAN_FILTER
#endif
#ifndef DEV_RX_OFFLOAD_VLAN_EXTEND
#define DEV_RX_OFFLOAD_VLAN_EXTEND RTE_ETH_RX_OFFLOAD_VLAN_EXTEND
#endif
#ifndef DEV_RX_OFFLOAD_SCATTER
#define DEV_RX_OFFLOAD_SCATTER RTE_ETH_RX_OFFLOAD_SCATTER
#endif
#ifndef DEV_RX_OFFLOAD_TIMESTAMP
#define DEV_RX_OFFLOAD_TIMESTAMP RTE_ETH_RX_OFFLOAD_TIMESTAMP
#endif
#ifndef DEV_RX_OFFLOAD_SECURITY
#define DEV_RX_OFFLOAD_SECURITY RTE_ETH_RX_OFFLOAD_SECURITY
#endif
#ifndef DEV_RX_OFFLOAD_KEEP_CRC
#define DEV_RX_OFFLOAD_KEEP_CRC RTE_ETH_RX_OFFLOAD_KEEP_CRC
#endif
#ifndef DEV_RX_OFFLOAD_JUMBO_FRAME
#define DEV_RX_OFFLOAD_JUMBO_FRAME 0x0
#endif

#ifndef RTE_FC_NONE
#define RTE_FC_NONE RTE_ETH_FC_NONE
#endif
#ifndef RTE_FC_RX_PAUSE
#define RTE_FC_RX_PAUSE RTE_ETH_FC_RX_PAUSE
#endif
#ifndef RTE_FC_TX_PAUSE
#define RTE_FC_TX_PAUSE RTE_ETH_FC_TX_PAUSE
#endif
#ifndef RTE_FC_FULL
#define RTE_FC_FULL RTE_ETH_FC_FULL
#endif
#ifndef DEV_RX_OFFLOAD_SCTP_CKSUM
#define DEV_RX_OFFLOAD_SCTP_CKSUM RTE_ETH_RX_OFFLOAD_SCTP_CKSUM
#endif
#ifndef DEV_RX_OFFLOAD_OUTER_UDP_CKSUM
#define DEV_RX_OFFLOAD_OUTER_UDP_CKSUM RTE_ETH_RX_OFFLOAD_OUTER_UDP_CKSUM
#endif
#ifndef DEV_RX_OFFLOAD_RSS_HASH
#define DEV_RX_OFFLOAD_RSS_HASH RTE_ETH_RX_OFFLOAD_RSS_HASH
#endif

#ifndef DEV_TX_OFFLOAD_VLAN_INSERT
#define DEV_TX_OFFLOAD_VLAN_INSERT RTE_ETH_TX_OFFLOAD_VLAN_INSERT
#endif
#ifndef DEV_TX_OFFLOAD_IPV4_CKSUM
#define DEV_TX_OFFLOAD_IPV4_CKSUM RTE_ETH_TX_OFFLOAD_IPV4_CKSUM
#endif
#ifndef DEV_TX_OFFLOAD_UDP_CKSUM
#define DEV_TX_OFFLOAD_UDP_CKSUM RTE_ETH_TX_OFFLOAD_UDP_CKSUM
#endif
#ifndef DEV_TX_OFFLOAD_TCP_CKSUM
#define DEV_TX_OFFLOAD_TCP_CKSUM RTE_ETH_TX_OFFLOAD_TCP_CKSUM
#endif
#ifndef DEV_TX_OFFLOAD_SCTP_CKSUM
#define DEV_TX_OFFLOAD_SCTP_CKSUM RTE_ETH_TX_OFFLOAD_SCTP_CKSUM
#endif
#ifndef DEV_TX_OFFLOAD_TCP_TSO
#define DEV_TX_OFFLOAD_TCP_TSO RTE_ETH_TX_OFFLOAD_TCP_TSO
#endif
#ifndef DEV_TX_OFFLOAD_UDP_TSO
#define DEV_TX_OFFLOAD_UDP_TSO RTE_ETH_TX_OFFLOAD_UDP_TSO
#endif
#ifndef DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM
#define DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM
#endif
#ifndef DEV_TX_OFFLOAD_QINQ_INSERT
#define DEV_TX_OFFLOAD_QINQ_INSERT RTE_ETH_TX_OFFLOAD_QINQ_INSERT
#endif
#ifndef DEV_TX_OFFLOAD_VXLAN_TNL_TSO
#define DEV_TX_OFFLOAD_VXLAN_TNL_TSO RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO
#endif
#ifndef DEV_TX_OFFLOAD_GRE_TNL_TSO
#define DEV_TX_OFFLOAD_GRE_TNL_TSO RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO
#endif
#ifndef DEV_TX_OFFLOAD_IPIP_TNL_TSO
#define DEV_TX_OFFLOAD_IPIP_TNL_TSO RTE_ETH_TX_OFFLOAD_IPIP_TNL_TSO
#endif
#ifndef DEV_TX_OFFLOAD_GENEVE_TNL_TSO
#define DEV_TX_OFFLOAD_GENEVE_TNL_TSO RTE_ETH_TX_OFFLOAD_GENEVE_TNL_TSO
#endif
#ifndef DEV_TX_OFFLOAD_MACSEC_INSERT
#define DEV_TX_OFFLOAD_MACSEC_INSERT RTE_ETH_TX_OFFLOAD_MACSEC_INSERT
#endif
#ifndef DEV_TX_OFFLOAD_MT_LOCKFREE
#define DEV_TX_OFFLOAD_MT_LOCKFREE RTE_ETH_TX_OFFLOAD_MT_LOCKFREE
#endif
#ifndef DEV_TX_OFFLOAD_MULTI_SEGS
#define DEV_TX_OFFLOAD_MULTI_SEGS RTE_ETH_TX_OFFLOAD_MULTI_SEGS
#endif
#ifndef DEV_TX_OFFLOAD_MBUF_FAST_FREE
#define DEV_TX_OFFLOAD_MBUF_FAST_FREE RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
#endif
#ifndef DEV_TX_OFFLOAD_SECURITY
#define DEV_TX_OFFLOAD_SECURITY RTE_ETH_TX_OFFLOAD_SECURITY
#endif
#ifndef DEV_TX_OFFLOAD_UDP_UXO
#define DEV_TX_OFFLOAD_UDP_UXO RTE_ETH_TX_OFFLOAD_UDP_UXO
#endif
#ifndef DEV_TX_OFFLOAD_SEND_ON_TIMESTAMP
#define DEV_TX_OFFLOAD_SEND_ON_TIMESTAMP RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP
#endif

#ifndef ETH_MQ_RX_NONE
#define ETH_MQ_RX_NONE RTE_ETH_MQ_RX_NONE
#endif
#ifndef ETH_MQ_RX_RSS
#define ETH_MQ_RX_RSS RTE_ETH_MQ_RX_RSS
#endif
#ifndef ETH_MQ_RX_DCB
#define ETH_MQ_RX_DCB RTE_ETH_MQ_RX_DCB
#endif
#ifndef ETH_MQ_RX_DCB_RSS
#define ETH_MQ_RX_DCB_RSS RTE_ETH_MQ_RX_DCB_RSS
#endif
#ifndef ETH_MQ_RX_VMDQ_ONLY
#define ETH_MQ_RX_VMDQ_ONLY RTE_ETH_MQ_RX_VMDQ_ONLY
#endif
#ifndef ETH_MQ_RX_VMDQ_RSS
#define ETH_MQ_RX_VMDQ_RSS RTE_ETH_MQ_RX_VMDQ_RSS
#endif
#ifndef ETH_MQ_RX_VMDQ_DCB
#define ETH_MQ_RX_VMDQ_DCB RTE_ETH_MQ_RX_VMDQ_DCB
#endif
#ifndef ETH_MQ_RX_VMDQ_DCB_RSS
#define ETH_MQ_RX_VMDQ_DCB_RSS RTE_ETH_MQ_RX_VMDQ_DCB_RSS
#endif

/*
 * Debian trixie's linux-vyatta kernel headers already ship linux/mpls.h
 * with these as real enumerators (RTMPA_TYPE, RTMPA_NH_FLAGS, etc, with
 * RTMPT_* values that differ from the placeholders below). #ifndef can't
 * detect an enumerator (it's not a macro), so guard on the header's own
 * include guard (_MPLS_H) instead -- otherwise this shim both fails to
 * compile (enumerator redeclaration) and, for the plain #define cases,
 * would silently shadow the kernel's real values with wrong ones.
 */
#ifndef _MPLS_H
#ifndef RTMPT_IP
#define RTMPT_IP 0
#endif
#ifndef RTMPT_IPV4
#define RTMPT_IPV4 1
#endif
#ifndef RTMPT_IPV6
#define RTMPT_IPV6 2
#endif

#ifndef RTMPA_TYPE
enum {
	RTMPA_UNSPEC,
	RTMPA_TYPE,
	RTMPA_NH_FLAGS,
	__RTMPA_MAX,
};
#define RTMPA_MAX (__RTMPA_MAX - 1)
#endif
#ifndef RTMPNF_BOS_ONLY
#define RTMPNF_BOS_ONLY 1
#endif
#ifndef RTA_MPLS_PAYLOAD
#define RTA_MPLS_PAYLOAD 30
#endif
#endif /* !_MPLS_H */

#ifndef RTE_LOGTYPE_LPM
#define RTE_LOGTYPE_LPM RTE_LOGTYPE_USER1
#endif

#ifndef ETH_RSS_IP
#define ETH_RSS_IP RTE_ETH_RSS_IP
#endif
#ifndef ETH_RSS_UDP
#define ETH_RSS_UDP RTE_ETH_RSS_UDP
#endif
#ifndef ETH_RSS_TCP
#define ETH_RSS_TCP RTE_ETH_RSS_TCP
#endif
#ifndef ETH_RSS_SCTP
#define ETH_RSS_SCTP RTE_ETH_RSS_SCTP
#endif

#ifndef rte_sched_port_config_v2
#define rte_sched_port_config_v2(params, q_array_size) rte_sched_port_config(params)
#endif
#ifndef rte_sched_subport_config_v2
#define rte_sched_subport_config_v2(port, subport, params, qsize, red_params) rte_sched_subport_config(port, subport, params, 0)
#endif
#ifndef rte_sched_pipe_config_v2
#define rte_sched_pipe_config_v2(port, subport, pipe, profile, port_params) rte_sched_pipe_config(port, subport, pipe, profile)
#endif
/*
 * DPDK 21.05 added the port handle as the first argument, and it is
 * dereferenced -- the scheduler reads its queue geometry to pack the
 * hierarchy path into the mbuf. Passing NULL segfaults in the data path as
 * soon as QoS actually forwards a packet:
 *
 *     rte_sched_port_pkt_write+0x4
 *     qos_sched
 *
 * The caller has the port in qinfo->dev_info.dpdk.port, so take it.
 */
#ifndef rte_sched_port_pkt_write_v2
#define rte_sched_port_pkt_write_v2(port, pkt, subport, pipe, tc, queue, color, dscp) \
	rte_sched_port_pkt_write(port, pkt, subport, pipe, tc, queue, color)
#endif
#ifndef rte_red_free_q_params
#define rte_red_free_q_params(pp, i) (void)0
#endif

#endif /* COMPAT_H */
