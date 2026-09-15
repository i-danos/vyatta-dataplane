#ifndef VRF_INTERNAL_H
#define VRF_INTERNAL_H
/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stddef.h>
#include <stdint.h>
#include <urcu.h>

#include "arp.h"
#include "compat.h"
#include "if/gre.h"
#include "ip_mcast.h"
#include "netinet/ip_mroute.h"
#include "netinet6/ip6_mroute.h"
#include "netinet6/route_v6.h"
#include "netlink.h" /* for kernel compat defines */
#include "route.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "vrf.h"

struct npf_config;
struct npf_alg_instance;
struct npf_timeout;
struct apt_instance;

struct vrf_per_core_stats {
	struct ipstats_mib ip;
	struct ipstats_mib ip6;
};

struct crypto_vrf_ctx;

struct vrf {
	struct route_head v_rt4_head;
	struct route6_head v_rt6_head;
	struct gre_infotbl_st *v_gre_infos;
	struct vti_ctxt_table *v_vti_contexts;
	vrfid_t    v_id;
	uint32_t    v_ref_count;
	uint16_t   v_ip_post_rlkup_features;
	uint16_t   v_ipv6_post_rlkup_features;
	char SPARE[4];
	/* --- cacheline 1 boundary (64 bytes) --- */
	uint32_t  *v_pbrtablemap;
	struct cds_lfht *v_ipv4_frag_table;
	struct cds_lfht *v_ipv6_frag_table;
	struct mcast_vrf v_mvrf4;
	struct mcast6_vrf v_mvrf6;
	struct crypto_vrf_ctx *crypto;
	struct npf_config *v_npf;
	struct npf_alg_instance *v_ai;
	struct apt_instance *v_apt;
	struct npf_timeout *v_to;
	struct cds_lfht *v_rt_tracker_tbl;

	struct rcu_head rcu;
	char v_name[VRF_NAME_SIZE];
	/*
	 * The VRF interface's own name -- "vrfRED" where v_name is "RED".
	 *
	 * Both exist because they answer to different readers. DANOS's CLI
	 * calls the routing instance RED and an operator expects that word;
	 * the kernel and zebra both call the device vrfRED, and an identity
	 * that a Desired side has to produce must be the one they use. The
	 * object key carries this, the display carries the other.
	 *
	 * Without it the two sides disagreed on every route in every
	 * non-default VRF: "vrf:vrfRED" against "vrf:RED", measured.
	 */
	char v_ifname[VRF_NAME_SIZE + 4];
	uint32_t v_external_id;
	fal_object_t v_fal_obj;
	struct pd_obj_state_and_flags v_pd_state;

	/* SNMP Statistics */
	struct arp_stats v_arpstat;
	uint64_t v_icmpstats[ICMP_MIB_MAX];
	uint64_t v_icmp6stats[ICMP_MIB_MAX];
	struct vrf_per_core_stats v_stats[];
};

static_assert(offsetof(struct vrf, v_pbrtablemap) == 64,
	      "first cache line exceeded");

#define VRF_ID_KERNEL_MAX 4096
#define VRF_ID_UPLINK_COUNT 1
#define VRF_ID_MAX (VRF_ID_KERNEL_MAX + VRF_ID_UPLINK_COUNT)
#define VRF_UPLINK_ID VRF_ID_KERNEL_MAX
extern struct vrf *vrf_table[];

/* Array of VRF pointers */
static inline struct vrf *get_vrf(vrfid_t vrf_id)
{
	return likely(vrf_id < VRF_ID_MAX) ? vrf_table[vrf_id] : NULL;
}

static inline struct vrf *vrf_get_rcu_fast(vrfid_t vrf_id)
{
	assert(vrf_id < VRF_ID_MAX);
	return rcu_dereference(vrf_table[vrf_id]);
}

static inline struct vrf *vrf_get_rcu(vrfid_t vrf_id)
{
	return likely(vrf_id < VRF_ID_MAX) ?
		rcu_dereference(vrf_table[vrf_id]) : NULL;
}

static inline const char *vrf_get_name(vrfid_t vrf_id)
{
	struct vrf *vrf;

	vrf = vrf_get_rcu(vrf_id);
	return vrf ? vrf->v_name : "UNKNOWN";
}

/*
 * The VRF name a Desired side would use for this id.
 *
 * The numeric ids cannot be compared across that boundary at all. DANOS's
 * default VRF is VRF_DEFAULT_ID (1) and zebra's is 0, and for non-default VRFs
 * the two are separate namespaces that merely happen to both be integers --
 * one is the operator's id, the other is zebra's own numbering. Comparing them
 * makes every route look like drift, which is what a probe against a healthy
 * box reported before this existed.
 *
 * v_name is filled from a "vrfX" interface, and the default VRF has none, so
 * it is empty there rather than absent. "default" is what zebra calls it.
 */
static inline const char *vrf_get_external_name(vrfid_t vrf_id)
{
	struct vrf *vrf;

	vrf = vrf_get_rcu(vrf_id);
	if (!vrf)
		return "unknown";
	if (vrf->v_ifname[0] == '\0')
		return "default";

	return vrf->v_ifname;
}

static inline vrfid_t vrf_get_next(vrfid_t vrf_id, struct vrf **vrf)
{
	for (*vrf = NULL;
	     !*vrf && vrf_id < VRF_ID_MAX;
	     *vrf = vrf_get_rcu(++vrf_id))
		;
	return vrf_id;
}

static inline bool is_nondefault_vrf(vrfid_t vrf_id)
{
	/*
	 * Uplink VRF is equivalent to the default VRF for the uplink
	 * source (local controller).
	 */
	return vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID;
}

static inline bool vrf_is_vrf_table_id(uint32_t tableid)
{
	return tableid > RT_TABLE_LOCAL;
}

#define DP_LOG_W_VRF(l, t, vrf_id, fmt, args...) do {			\
		if (vrf_id > VRF_DEFAULT_ID)				\
			RTE_LOG(l, t, "[%s] ID: %u " fmt,		\
				vrf_get_name(vrf_id), vrf_id, ## args);	\
		else							\
			RTE_LOG(l, t, fmt, ## args);			\
	} while (0)

#define DP_DEBUG_W_VRF(m, l, t, vrf_id, fmt, args...) do {		\
		if (unlikely(dp_debug & DP_DBG_##m))			\
			DP_LOG_W_VRF(l, t, vrf_id,  fmt, ## args);	\
	} while (0)

#define VRF_FOREACH(vrf, vrf_id)				\
	for (vrf_id = vrf_get_next(VRF_DEFAULT_ID - 1, &vrf);	\
	     vrf_id < VRF_ID_MAX;				\
	     vrf_id = vrf_get_next(vrf_id, &vrf))

#define VRF_FOREACH_KERNEL(vrf, vrf_id)				\
	for (vrf_id = vrf_get_next(VRF_DEFAULT_ID - 1, &vrf);	\
		vrf_id < VRF_ID_KERNEL_MAX;			\
		vrf_id = vrf_get_next(vrf_id, &vrf))

#define VRF_FOREACH_UPLINK(vrf, vrf_id)					\
	for (vrf_id = vrf_get_next(VRF_ID_KERNEL_MAX - 1, &vrf);	\
		vrf_id < VRF_ID_MAX;					\
		vrf_id = vrf_get_next(vrf_id, &vrf))

struct vrf *vrf_handle_netlink_create(uint32_t vrf_id, struct nlattr *tb[]);
struct vrf *vrf_find_or_create(uint32_t vrf_id);
void vrf_delete_by_ptr(struct vrf *vrf);
void vrf_delete(uint32_t vrf_id);
void vrf_delete_all(enum cont_src_en cont_src);
void vrf_init(void);
void vrf_cleanup(void);
void vrf_set_external_id(struct vrf *vrf, uint32_t external_id);
void vrf_set_name(struct vrf *vrf, const char *ifname);

uint32_t *vrf_table_hw_stats_get(void);
int vrf_table_get_pd_subset_data(json_writer_t *json,
				 enum pd_obj_state subset);

/*
 * Set up PBR tablemap in vrf to map PBR tables (1-128)
 * to kernel tableid.
 */
int cmd_tablemap_cfg(FILE *f, int argc, char **argv);

#endif /* VRF_INTERNAL_H */
