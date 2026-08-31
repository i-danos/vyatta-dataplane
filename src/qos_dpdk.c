
/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_red.h>
#include <rte_sched.h>
#include "qos.h"
#include "json_writer.h"
#include "netinet6/ip6_funcs.h"
#include "npf/config/npf_config.h"
#include "npf_shim.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "ether.h"

/*
 * Only allow a child shaper to use 99.6% of the parent bandwidth so when we
 * borrow tokens we don't set the time into the future.
 * 99.6 was chosen by testing, no failures were seen using it.  If the time
 * is incorrectly advanced we drop the packets on the backplane which is far
 * harder to diagnose so forcing them into the shaper is preferrable.
 */
#define	MAX_RATE_FLOAT	99.6
#define	MAX_RATE_SCALED	996

uint64_t qos_dpdk_check_rate(uint64_t rate, uint64_t parent_bw)
{
	/*
	 * Check whether the rate is close or equal to the parent bandwidth.
	 * If it is we may run into time issues when borrowing tokens which
	 * turns off the shaper so make sure we only set the rate to 99.6%
	 * of the parent
	 */
	if (parent_bw) {
		float percent;

		percent = (((float)rate * 100.0) / (float)parent_bw);
		if (percent > MAX_RATE_FLOAT) {
			uint64_t tmp_rate;

			tmp_rate = (uint64_t)parent_bw * MAX_RATE_SCALED;
			rate = tmp_rate / 1000;
		}
	}
	return rate;
}

/*
 * Return the DSCP wred resource group name associated with a map entry
 * in a queue index.
 */
/*
 * DANOS keeps four traffic classes and gives each of them
 * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS queues. DPDK 21.05 onwards has a
 * different shape: RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE classes, of which all
 * but the last hold exactly one queue, and the last -- best effort,
 * RTE_SCHED_TRAFFIC_CLASS_BE -- holds RTE_SCHED_BE_QUEUES_PER_PIPE WRR
 * queues. With the values DPDK 24.11 ships that is thirteen classes over
 * sixteen queue slots per pipe, against DANOS's four over sixteen.
 *
 * Map DANOS's first three classes straight through and its last onto best
 * effort, which is where its WRR queues belong. Only these helpers speak
 * DPDK's numbering: qmap_to_tc()/qmap_to_wrr() and qos_sched_calc_qindex()
 * keep DANOS's, because the hardware offload path in qos_hw.c and the
 * per-queue statistics array are indexed with it.
 */
#define QOS_DANOS_TC_BE RTE_SCHED_TC_MASK	/* DANOS's last class, 3 */

static inline uint32_t qos_dpdk_tc(uint8_t q)
{
	uint8_t tc = qmap_to_tc(q);

	return tc < QOS_DANOS_TC_BE ? tc : RTE_SCHED_TRAFFIC_CLASS_BE;
}

/*
 * DANOS class index to DPDK's. Everything indexed by traffic class -- queue
 * sizes, TC rates in both the subport and the pipe profile -- has to go
 * through this, and consistently: DPDK requires tc_rate[i] to be non-zero
 * exactly when qsize[i] is, and rejects the profile otherwise.
 */
static inline uint32_t qos_dpdk_tc_index(uint32_t danos_tc)
{
	return danos_tc < QOS_DANOS_TC_BE ?
		danos_tc : RTE_SCHED_TRAFFIC_CLASS_BE;
}

/*
 * DANOS's queue within a class, expressed in DPDK's geometry.
 *
 * DANOS has eight queues per class; DPDK gives a single queue to every class
 * except best effort, which gets RTE_SCHED_BE_QUEUES_PER_PIPE (four). The two
 * do not fit, so:
 *
 *   classes 0-2  collapse to queue 0. DPDK schedules these strictly by
 *                priority and has nowhere to put a second queue, so the WRR
 *                weights configured within them cannot be honoured.
 *   class 3 (BE) folds eight onto four, pairwise. Relative ordering is kept
 *                and some weighting survives; queues 0-1 share DPDK queue 0,
 *                2-3 share 1, and so on.
 *
 * The alternative -- spreading DANOS's queues across several DPDK classes --
 * would turn weighting within a class into strict priority between classes,
 * which is a different thing from what was configured. A predictable
 * downgrade is preferable to silently changing what the configuration means.
 */
static inline uint32_t qos_dpdk_wrr(uint8_t q)
{
	if (qmap_to_tc(q) < QOS_DANOS_TC_BE)
		return 0;

	return qmap_to_wrr(q) /
		(RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS /
		 RTE_SCHED_BE_QUEUES_PER_PIPE);
}

/*
 * The queue index DPDK addresses, which is not the one DANOS uses for its own
 * arrays: DPDK reserves RTE_SCHED_QUEUES_PER_PIPE slots per pipe and places a
 * class at a fixed offset within them, rather than giving every class the same
 * number of queues.
 */
static inline uint32_t qos_dpdk_qindex(struct sched_info *qinfo,
				       uint32_t subport, uint32_t pipe,
				       uint32_t tc, uint32_t q)
{
	uint32_t dtc = tc < QOS_DANOS_TC_BE ? tc : RTE_SCHED_TRAFFIC_CLASS_BE;
	uint32_t dq = tc < QOS_DANOS_TC_BE ? 0 :
		q / (RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS /
		     RTE_SCHED_BE_QUEUES_PER_PIPE);
	uint32_t off = dtc < RTE_SCHED_TRAFFIC_CLASS_BE ?
		dtc : RTE_SCHED_TRAFFIC_CLASS_BE + dq;

	return (subport * qinfo->port_params.n_pipes_per_subport + pipe) *
		RTE_SCHED_QUEUES_PER_PIPE + off;
}

/*
 * Emit the WRED resource groups configured on one queue.
 *
 * This asked DPDK two questions it cannot answer -- which pipe profile a
 * pipe uses, and how many maps a queue has -- through compat.h shims that
 * returned 0 and 1. Both are ours to answer: qos_red_init_q_params() is
 * what fills these structures in, and sinfo->profile_map is what records
 * the pipe's profile. qos_hw_dscp_resgrp_json() has always read them
 * directly; this is the same walk.
 *
 * The lookup key was wrong on top of that. WRED parameters are stored
 * against the per-pipe queue index q_from_mask() builds, tc * 8 + q,
 * while what was passed here is qos_dpdk_qindex()'s port-wide queue id
 * -- (subport * pipes + pipe) * 16 + off. The two agree only on the
 * first pipe of the first subport, so qos_red_find_q_params() returned
 * NULL, qos_get_dscp_grp() returned NULL, and the loop broke on its
 * first iteration. The visible result was an empty "wred_map": [] on
 * every queue, which reads as "none configured" rather than as a defect.
 */
void qos_dpdk_dscp_resgrp_json(struct sched_info *qinfo, uint32_t subport,
			       uint32_t pipe, uint32_t tc, uint32_t q,
			       uint64_t *random_dscp_drop, json_writer_t *wr)
{
	struct subport_info *sinfo = qinfo->subport + subport;
	struct qos_red_pipe_params *wred;
	struct qos_pipe_params *prof;
	unsigned int qindex;
	uint8_t profile_id;
	int i;

	profile_id = sinfo->profile_map[pipe];
	if (profile_id >= qinfo->port_params.n_pipe_profiles)
		return;

	prof = &qinfo->port_params.pipe_profiles[profile_id];
	qindex = (tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS) + q;

	wred = qos_red_find_q_params(prof, qindex);
	if (!wred || !wred->red_q_params.num_maps)
		return;

	/*
	 * grp_names[] is indexed by wred_index, which is a running map
	 * number under wred-per-dscp and a drop precedence otherwise, so
	 * the bound is the array's own RTE_NUM_DSCP_MAPS rather than
	 * NUM_DPS. dps_in_use says which entries were filled;
	 * random_dscp_drop[] is indexed the same way.
	 */
	jsonw_name(wr, "wred_map");
	jsonw_start_array(wr);
	for (i = 0; i < RTE_NUM_DSCP_MAPS; i++) {
		char *grp_name = wred->red_q_params.grp_names[i];

		if (!(wred->red_q_params.dps_in_use & (1 << i)))
			continue;
		if (grp_name == NULL)
			continue;
		jsonw_start_object(wr);
		jsonw_string_field(wr, "res_grp", grp_name);
		jsonw_uint_field(wr, "random_dscp_drop", random_dscp_drop[i]);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

int qos_dpdk_subport_read_stats(struct sched_info *qinfo,
				uint32_t subport,
				struct rte_sched_subport_stats64 *queue_stats)
{
	uint32_t over[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	struct rte_sched_port *port = qinfo->dev_info.dpdk.port;
	struct rte_sched_subport_stats64 stats;
	int ret, i;

	rte_spinlock_lock(&qinfo->stats_lock);
	ret = rte_sched_subport_read_stats64(port, subport, &stats, over);
	if (ret == 0) {
		/*
		 * DPDK indexes these by its own traffic class, so best effort
		 * lands at RTE_SCHED_TRAFFIC_CLASS_BE while DANOS looks for
		 * its last class at index 3. Fold each DPDK class back onto
		 * the DANOS one it came from; the classes in between are not
		 * used and contribute nothing.
		 */
		for (i = 0; i <= (int)QOS_DANOS_TC_BE; i++) {
			uint32_t d = qos_dpdk_tc_index(i);

			queue_stats->n_pkts_tc[i] += stats.n_pkts_tc[d];
			queue_stats->n_bytes_tc[i] += stats.n_bytes_tc[d];
			queue_stats->n_pkts_tc_dropped[i] +=
				stats.n_pkts_tc_dropped[d];
			queue_stats->n_pkts_cman_dropped[i] +=
				stats.n_pkts_cman_dropped[d];
		}
	}
	rte_spinlock_unlock(&qinfo->stats_lock);

	return ret;
}

int qos_dpdk_subport_clear_stats(struct sched_info *qinfo, uint32_t subport)
{
	struct subport_info *sinfo = qinfo->subport + subport;
	struct rte_sched_subport_stats64 *queue_stats = &sinfo->queue_stats;
	struct rte_sched_subport_stats64 *clear_stats = &sinfo->clear_stats;
	uint32_t tc;

	/*
	 * Read the DPDK's subport counters to clear them.
	 */
	if (qos_dpdk_subport_read_stats(qinfo, subport, queue_stats) < 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Failed to read subport stats for subport: %u\n",
			 subport);
		return -1;
	}

	/*
	 * Copy the current queue_stats for each TC, into the clear_stats so
	 * that we can provide the difference between updated queue_stats and
	 * the clear_stats when we receive a "show stats" command.
	 */
	rte_spinlock_lock(&qinfo->stats_lock);
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		clear_stats->n_pkts_tc[tc] = queue_stats->n_pkts_tc[tc];
		clear_stats->n_bytes_tc[tc] = queue_stats->n_bytes_tc[tc];
		clear_stats->n_pkts_tc_dropped[tc] =
			queue_stats->n_pkts_tc_dropped[tc];
		clear_stats->n_bytes_tc_dropped[tc] =
			queue_stats->n_bytes_tc_dropped[tc];
		clear_stats->n_pkts_cman_dropped[tc] =
			queue_stats->n_pkts_cman_dropped[tc];
	}
	rte_spinlock_unlock(&qinfo->stats_lock);
	return 0;
}


int qos_dpdk_queue_read_stats(struct sched_info *qinfo,
			      uint32_t subport, uint32_t pipe,
			      uint32_t tc, uint32_t q,
			      struct queue_stats *queue_stats,
			      uint64_t *qlen, bool *qlen_in_pkts)
{
	struct rte_sched_queue_stats64 stats;
	struct rte_sched_port *port = qinfo->dev_info.dpdk.port;
	uint32_t qid = qos_dpdk_qindex(qinfo, subport, pipe, tc, q);
	uint16_t qlen_16;
	int ret;

	/*
	 * Several DANOS queues share one DPDK queue once the geometry is
	 * folded, and rte_sched_queue_read_stats64() clears what it returns.
	 * Reading from every one of them would hand the counts to whichever
	 * happened to be enumerated first and leave the rest at zero -- true,
	 * but true by accident, and it would change if the enumeration order
	 * ever did.
	 *
	 * Attribute the shared counts to the lowest DANOS queue of each group
	 * and report the others as empty without reading, so nothing consumes
	 * counts that belong to a queue it is not reporting. Those queues
	 * genuinely have no separate existence in the scheduler; see the
	 * mapping note above.
	 */
	if (tc >= QOS_DANOS_TC_BE &&
	    (q % (RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS /
		  RTE_SCHED_BE_QUEUES_PER_PIPE)) != 0) {
		*qlen = 0;
		*qlen_in_pkts = true;
		return 0;
	}

	/*
	 * The DPDK always measures queue length in the number of packets.
	 */
	*qlen_in_pkts = true;
	rte_spinlock_lock(&qinfo->stats_lock);
	ret = rte_sched_queue_read_stats64(port, qid, &stats, &qlen_16);
	if (ret == 0) {
		queue_stats->n_pkts += stats.n_pkts;
		queue_stats->n_bytes += stats.n_bytes;
		queue_stats->n_pkts_dropped += stats.n_pkts_dropped;
		queue_stats->n_pkts_red_dropped += stats.n_pkts_cman_dropped;
		*qlen = qlen_16;
	}
	rte_spinlock_unlock(&qinfo->stats_lock);

	return ret;
}

int qos_dpdk_queue_clear_stats(struct sched_info *qinfo,
			       uint32_t subport, uint32_t pipe,
			       uint32_t tc, uint32_t q)
{
	uint32_t qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc, q);
	struct queue_stats *queue_stats = qinfo->queue_stats + qid;
	bool qlen_in_pkts;
	uint64_t qlen;
	uint32_t i;
	int rv;

	rv = qos_dpdk_queue_read_stats(qinfo, subport, pipe, tc, q, queue_stats,
				       &qlen, &qlen_in_pkts);
	if (rv == 0) {
		/*
		 * Remember the value the dataplane's counters when they were
		 * cleared.
		 */
		rte_spinlock_lock(&qinfo->stats_lock);
		queue_stats->n_pkts_lc = queue_stats->n_pkts;
		queue_stats->n_bytes_lc = queue_stats->n_bytes;
		queue_stats->n_pkts_dropped_lc = queue_stats->n_pkts_dropped;
		queue_stats->n_pkts_red_dropped_lc =
			queue_stats->n_pkts_red_dropped;
		for (i = 0; i < RTE_NUM_DSCP_MAPS; i++)
			queue_stats->n_pkts_red_dscp_dropped_lc[i] =
				queue_stats->n_pkts_red_dscp_dropped[i];
		rte_spinlock_unlock(&qinfo->stats_lock);
	}
	return rv;
}

void qos_dpdk_free(struct sched_info *qinfo)
{
	if (qinfo->dev_info.dpdk.port)
		rte_sched_port_free(qinfo->dev_info.dpdk.port);
}

int qos_dpdk_port(struct ifnet *ifp,
		  unsigned int subports, unsigned int pipes,
		  unsigned int profiles, unsigned int overhead)
{
	unsigned int n_subports, n_pipes;

	n_subports = subports;
	subports = rte_align32pow2(subports);

	if (pipes == 0 || pipes > RTE_SCHED_PIPE_PROFILES_PER_PORT) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE, "bad pipes value: %u\n",
			 pipes);
		return -EINVAL;
	}
	n_pipes = pipes;
	pipes = rte_align32pow2(pipes);

	if (profiles == 0 || profiles > RTE_SCHED_PIPE_PROFILES_PER_PORT) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE, "bad profiles value: %u\n",
			 profiles);
		return -EINVAL;
	}

	/* Intel code has silent requirement that:
	 * queues_per_pipe * n_pipes_per_subport * n_subports % 512 == 0
	 * See RTE_BITMAP_CL_BIT_SIZE
	 */
	unsigned int queues = RTE_SCHED_QUEUES_PER_PIPE * subports * pipes;

	queues = RTE_ALIGN(queues, RTE_CACHE_LINE_SIZE * 8);
	pipes = queues / (RTE_SCHED_QUEUES_PER_PIPE * subports);

	DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,
		 "Rounded to subports %u pipes %u profiles %u\n",
		 subports, pipes, profiles);

	/* Drop old config if any */
	struct sched_info *qinfo = ifp->if_qos;

	if (qinfo) {
		RTE_LOG(INFO, DATAPLANE, "Removing existing QoS SW config from %s\n",
			ifp->if_name);
		qos_sched_disable(ifp, qinfo);
	}

	qinfo = qos_sched_new(ifp, subports, pipes, profiles, overhead);
	if (!qinfo) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE, "out of memory for qos\n");
		return -ENOMEM;
	}

	qinfo->n_subports = n_subports;
	qinfo->n_pipes = n_pipes;
	qinfo->dev_id = QOS_DPDK_ID;

	rcu_assign_pointer(ifp->if_qos, qinfo);
	return 0;
}

int qos_dpdk_disable(struct ifnet *ifp, struct sched_info *qinfo)
{
	qos_dpdk_stop(ifp, qinfo);
	rcu_assign_pointer(ifp->if_qos, NULL);

	qos_subport_npf_free(qinfo);
	call_rcu(&qinfo->rcu, qos_sched_free_rcu);

	return 0;
}

int qos_dpdk_enable(struct ifnet *ifp,
		    struct sched_info *qinfo)
{
	struct dp_ifnet_link_status link;

	if (!ifp->hw_forwarding) {
		/* If link is already up, then start now */
		dp_ifnet_link_status(ifp, &link);

		if (link.link_status &&
		    link.link_speed != ETH_SPEED_NUM_NONE &&
		    qos_sched_start(ifp, link.link_speed) < 0) {
			DP_DEBUG(QOS_DP, ERR, DATAPLANE, "Qos start failed\n");
			qinfo->enabled = false;
			return -ENODEV;
		}
		DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,
			 "link status %s, speed %d, QoS not started\n",
			 link.link_status ? "up" : "down",
			 link.link_speed);
	} else {
		DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,
			 "interface not sw forwarding, QoS not started\n");
	}

	return 0;
}

/* Callback after all forwarding threads have cleared. */
static void qos_dpdk_port_free_rcu(void *arg)
{
	rte_sched_port_free(arg);
}

/* Return the total queue-array length for the subport.
 * If the subport doesn't have its TC queue-limits explicitly defined inherit
 * the port's queue-limits.
 */
static uint32_t qos_sched_subport_qsize(struct qos_port_params *pp,
					struct subport_info *sinfo)
{
	uint32_t queue_array_size = 0;
	uint32_t tc;

	/* DANOS's classes: qos_sp_qsize_get() reads sinfo->qsize[]. */
	for (tc = 0; tc < QOS_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		uint32_t qsize = qos_sp_qsize_get(pp, sinfo, tc);
		queue_array_size += qsize;
	}

	return (queue_array_size * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS *
		pp->n_pipes_per_subport * sizeof(struct rte_mbuf *));
}

/*
 * Bring a queue size into the shape stock DPDK accepts.
 *
 * rte_sched_subport_check_params() rejects the whole subport unless every
 * non-zero qsize is a power of two -- rte_sched.c:839, "no bigger than 32K
 * (due to 16-bit read/write pointers)". DANOS's queue-limit is a plain count
 * of packets or bytes and is rounded nowhere, so a configuration as ordinary
 * as "queue-limit 100" made rte_sched_subport_config() return -EINVAL and
 * took the entire QoS policy with it. The default is 64, which is a power of
 * two, which is why this was not noticed.
 *
 * The value also used to arrive through a (uint16_t) cast, so anything at or
 * above 65536 wrapped first: 70000 became 4464, not a power of two either,
 * and unrelated to what was asked for.
 *
 * Round down, and say so. Rounding up would hand out more buffering than was
 * configured, and rounding down is what the USEC path already does when it
 * passes its own limits.
 */
#define QOS_DPDK_MAX_QSIZE 32768

static uint16_t qos_dpdk_qsize(uint32_t qsize)
{
	uint32_t rounded;

	if (qsize == 0)
		return 0;

	if (qsize > QOS_DPDK_MAX_QSIZE)
		qsize = QOS_DPDK_MAX_QSIZE;

	rounded = rte_align32prevpow2(qsize);
	if (rounded != qsize)
		RTE_LOG(INFO, DATAPLANE,
			"Rounding down queue size from %u to %u\n",
			qsize, rounded);

	return (uint16_t)rounded;
}

/*
 * Bring a RED threshold into the range stock DPDK accepts.
 *
 * The DANOS DPDK fork carried rte_red_set_scaling(), called once from
 * qos_init() with MAX_RED_QUEUE_LENGTH (8192), which widened RED's
 * fixed-point threshold field. Stock DPDK has no such knob:
 * RTE_RED_MAX_TH_MAX is 1023 and rte_red_config_init() rejects anything
 * above it. compat.h stubbed the call out as a constant 0 -- reporting
 * success, doing nothing -- and left the thresholds to arrive unchanged.
 *
 * Nothing checked them on the way. qos_wred_threshold_get() range-checks
 * only its QOS_QUEUE_SIZE_USEC branch, and even that clamps no lower than
 * MAX_QUEUE_LIMIT_BYTES (500000000); the packets and bytes branches pass
 * the value straight through. It was then cast to uint16_t, so a
 * threshold of 70000 arrived as 4464 -- not merely too large but
 * arbitrary, and smaller than a neighbour that had not wrapped.
 *
 * Clamping loses precision on queues longer than 1023. Failing loses
 * more: rte_red_config_init()'s error propagates out of
 * rte_sched_subport_config(), so one over-long threshold would take the
 * whole policy's shaping down with it. Clamp, and say so -- which is what
 * the USEC branch already does for its own limits.
 */
static uint16_t qos_red_clamp_th(uint32_t th, const char *what)
{
	if (th <= RTE_RED_MAX_TH_MAX)
		return (uint16_t)th;

	RTE_LOG(INFO, DATAPLANE, "Rounding down RED %s from %u to %d\n",
		what, th, RTE_RED_MAX_TH_MAX);
	return RTE_RED_MAX_TH_MAX;
}

static void qos_copy_red_params(struct rte_red_params
						dpdk[][RTE_COLORS],
				struct subport_info *sinfo)
{
	int i, j;

	/*
	 * The caller's array is DPDK-shaped and not initialised, so clear the
	 * classes DANOS does not fill rather than leave them holding stack.
	 */
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		for (j = 0; j < RTE_COLORS; j++)
			dpdk[i][j] = (struct rte_red_params){ 0 };

	/* Read at DANOS's class index, write at DPDK's. */
	for (i = 0; i < QOS_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint32_t d = qos_dpdk_tc_index(i);

		for (j = 0; j < RTE_COLORS; j++) {
			uint32_t wred_min_th = 0;
			uint32_t wred_max_th = 0;
			qos_wred_threshold_get(&sinfo->red_params[i][j],
					sinfo->params.tc_rate[i],
					&wred_min_th, &wred_max_th);

			dpdk[d][j].min_th = qos_red_clamp_th(wred_min_th,
							     "min_th");
			dpdk[d][j].max_th = qos_red_clamp_th(wred_max_th,
							     "max_th");
			dpdk[d][j].maxp_inv =
				(uint16_t)sinfo->red_params[i][j].maxp_inv;
			dpdk[d][j].wq_log2 =
				(uint16_t)sinfo->red_params[i][j].wq_log2;
		}
	}
}

/*
 * Build the pipe profile table a subport is configured with.
 *
 * DPDK 21.05 moved pipe profiles from the port to the subport:
 * rte_sched_port_params lost n_pipe_profiles/pipe_profiles and gained a table
 * of subport profiles instead, while the pipe profiles became a member of
 * rte_sched_subport_params. The two are unrelated -- a subport profile is a
 * shaper (rates and a token bucket), a pipe profile also carries WRR weights.
 * Caller owns the returned array.
 */
static struct rte_sched_pipe_params *
qos_dpdk_build_pipe_profiles(struct qos_port_params *qos_params)
{
	struct rte_sched_pipe_params *profiles;
	unsigned int i, j;

	profiles = calloc(qos_params->n_pipe_profiles, sizeof(*profiles));
	if (!profiles)
		return NULL;

	for (i = 0; i < qos_params->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *to = &profiles[i];
		struct qos_pipe_params *from = qos_params->pipe_profiles + i;

		to->tc_period = from->shaper.tc_period;
		to->tb_size = from->shaper.tb_size;
		to->tb_rate = from->shaper.tb_rate;

		/*
		 * DPDK requires a non-zero oversubscription weight and
		 * rejects the profile without one:
		 *
		 *     pipe_profile_check: Incorrect value for tc ov weight
		 *
		 * The field is called tc_ov_weight, and the assignment used
		 * to name tc_tc_ov_weight guarded by RTE_SCHED_SUBPORT_TC_OV,
		 * a macro DPDK 24.11 does not define -- so it never compiled
		 * in and the field stayed at zero.
		 */
		to->tc_ov_weight = from->shaper.tc_ov_weight ?
			from->shaper.tc_ov_weight : 1;

		/*
		 * Only the best-effort traffic class carries WRR weights, and
		 * DPDK sizes the array by RTE_SCHED_BE_QUEUES_PER_PIPE (4).
		 * DANOS keeps one per queue, RTE_SCHED_QUEUES_PER_PIPE (16),
		 * so copying the whole DANOS array wrote twelve bytes past
		 * the end of the DPDK structure.
		 */
		/*
		 * DPDK's WRR weights belong to the best-effort class, so take
		 * them from DANOS's best-effort queues -- indices QMAP(TC_BE,
		 * n) -- rather than from the start of the array, which is
		 * class 0. Two DANOS queues fold onto each DPDK one, and the
		 * lower of the pair supplies the weight, matching how the
		 * statistics are attributed.
		 */
		for (j = 0; j < RTE_SCHED_BE_QUEUES_PER_PIPE; j++) {
			unsigned int dq = j * (RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS
					       / RTE_SCHED_BE_QUEUES_PER_PIPE);

			to->wrr_weights[j] =
				from->wrr_weights[QMAP(QOS_DANOS_TC_BE, dq)];
		}
		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++)
			to->tc_rate[j] = 0;
		for (j = 0; j <= QOS_DANOS_TC_BE; j++)
			to->tc_rate[qos_dpdk_tc_index(j)] =
				from->shaper.tc_rate[j];
	}
	return profiles;
}

static int qos_dpdk_setup_params(struct ifnet *ifp, struct sched_info *qinfo,
				 struct rte_sched_port_params *dpdk_port_params)
{
	struct qos_port_params *qos_params = &qinfo->port_params;
	int socketid = rte_eth_dev_socket_id(ifp->if_port);
	struct rte_sched_subport_profile_params *subport_profiles;
	unsigned int i, j;

	/*
	 * One subport profile per subport, referenced by index when the
	 * subport is configured. This used to hand DPDK the pipe profile
	 * array cast to a subport profile pointer, which is wrong on both
	 * counts: the structures differ in layout, so the stride was wrong
	 * past the first element, and the array was never filled in at all --
	 * calloc leaves tb_rate at 0, which rte_sched_port_check_params()
	 * rejects with
	 *
	 *     Incorrect value for subport profiles
	 *     Port scheduler params check failed (-22)
	 *
	 * so "qos <interface> enable" failed outright.
	 */
	subport_profiles = calloc(qinfo->n_subports, sizeof(*subport_profiles));
	if (!subport_profiles)
		return -1;

	for (i = 0; i < qinfo->n_subports; i++) {
		struct rte_sched_subport_profile_params *to =
			&subport_profiles[i];
		struct qos_shaper_conf *from = &qinfo->subport[i].params;

		to->tb_rate = from->tb_rate;
		to->tb_size = from->tb_size;
		to->tc_period = from->tc_period;
		/*
		 * DPDK checks a subport profile differently from a pipe
		 * profile: every tc_rate must be non-zero here, whereas in a
		 * pipe profile it must be non-zero exactly where qsize is.
		 *
		 * DANOS has four classes, so the classes it does not use are
		 * given the subport's own rate. They carry no queues and no
		 * traffic; the value only has to be non-zero for DPDK to
		 * accept the profile.
		 */
		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++)
			to->tc_rate[j] = from->tb_rate;
		for (j = 0; j < QOS_TRAFFIC_CLASSES_PER_PIPE; j++)
			to->tc_rate[qos_dpdk_tc_index(j)] = from->tc_rate[j];
	}

	if (socketid < 0) /* SOCKET_ID_ANY */
		socketid = 0;

	dpdk_port_params->socket = socketid;
	dpdk_port_params->subport_profiles = subport_profiles;
	dpdk_port_params->n_subport_profiles = qinfo->n_subports;
	dpdk_port_params->n_max_subport_profiles = qinfo->n_subports;
	dpdk_port_params->rate = qos_params->rate;
	dpdk_port_params->mtu = qos_params->mtu;
	dpdk_port_params->frame_overhead = qos_params->frame_overhead;
	dpdk_port_params->n_subports_per_port = qos_params->n_subports_per_port;
	dpdk_port_params->n_pipes_per_subport = qos_params->n_pipes_per_subport;

	return 0;
}

static void qos_dpdk_free_params(struct rte_sched_port_params *dpdk_port_params)
{
	free(dpdk_port_params->subport_profiles);
	dpdk_port_params->subport_profiles = NULL;
}

/* Allocate and initialize a handle to QoS scheduler.
 * Only called by main thread.
 */
int qos_dpdk_start(struct ifnet *ifp, struct sched_info *qinfo,
		   uint64_t bps, uint16_t max_pkt_len)
{
	struct rte_sched_port *port, *old_port = NULL;
	unsigned int subport, pipe;
	int ret;
	uint32_t q_array_size;
	struct rte_sched_port_params dpdk_port_params = {0};
	struct rte_sched_pipe_params *pipe_profiles = NULL;
	const uint32_t max_burst_size = QOS_MAX_BURST_SIZE_DPDK;

	if (enable_transmit_thread(ifp->if_port) < 0) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "Transmit thread setup failed on %s, portid %u\n",
			 ifp->if_name, ifp->if_port);
		qinfo->enabled = false;
		return -ENODEV;
	}

	ifp->qos_software_fwd = 1;

	/*
	 * Allow subports to inherit their queue sizes from the port, and
	 * calculate the total size of queue array this port will need.
	 */
	q_array_size = 0;
	for (subport = 0; subport < qinfo->n_subports; subport++) {
		struct subport_info *sinfo = &qinfo->subport[subport];

		q_array_size += qos_sched_subport_qsize(&qinfo->port_params,
							sinfo);

		/*
		 * If we've received a rate auto we use the reported
		 * interface speed as the subport rate.
		 */
		if (sinfo->auto_speed)
			qos_abs_rate_save(&sinfo->subport_rate, bps);

		/*
		 * Establish subport rates before checking pipes so that the
		 * pipes can be checked against their actual subport rates.
		 */
		qos_sched_subport_params_check(
			&sinfo->params, &sinfo->subport_rate,
			sinfo->sp_tc_rates.tc_rate, max_pkt_len,
			max_burst_size, bps, qinfo);
	}

	qos_sched_pipe_check(qinfo, max_pkt_len, max_burst_size, bps);

	if (qos_dpdk_setup_params(ifp, qinfo, &dpdk_port_params)) {
		qos_dpdk_free_params(&dpdk_port_params);
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "QoS DPDK config setup failed\n");
		goto out_disable_tx;
	}

	/*
	 * Built once and shared by every subport, so it has to outlive the
	 * subport loop below rather than being freed with the port params.
	 */
	pipe_profiles = qos_dpdk_build_pipe_profiles(&qinfo->port_params);
	if (!pipe_profiles) {
		qos_dpdk_free_params(&dpdk_port_params);
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "QoS pipe profile setup failed\n");
		goto out_disable_tx;
	}

	port = rte_sched_port_config_v2(&dpdk_port_params, q_array_size);
	if (port == NULL) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "QoS config port failed\n");
		qos_dpdk_free_params(&dpdk_port_params);
		free(pipe_profiles);
		goto out_disable_tx;
	}

	/*
	 * Every subport DPDK was told about has to be configured, not just
	 * the ones carrying configuration.
	 *
	 * qos_dpdk_port() rounds the subport count up to a power of two --
	 * n_subports = 3 becomes n_subports_per_port = 4 -- and keeps the
	 * real count separately. Only the real ones were configured here, so
	 * port->subports[3] stayed NULL, and rte_sched_port_dequeue() walks
	 * all n_subports_per_port entries and dereferences each one. That is
	 * a NULL dereference in the transmit path, which runs continuously
	 * once QoS is enabled whether or not there is traffic.
	 *
	 * It needed three subports to show: every other configuration in the
	 * test suite has a subport count that is already a power of two, so
	 * the rounding is a no-op and the gap never opens.
	 *
	 * The padding entries take subport 0's configuration and its subport
	 * profile. There are only n_subports profiles, and nothing is ever
	 * classified into these subports, so the values need only be valid.
	 */
	for (subport = 0; subport < qinfo->port_params.n_subports_per_port;
	     subport++) {
		uint32_t cfg = subport < qinfo->n_subports ? subport : 0;
		struct subport_info *sinfo = &qinfo->subport[cfg];
		struct rte_sched_subport_params dpdk_params = {0};
		struct rte_red_params
			dpdk_red_params[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE]
				       [RTE_COLORS];
		int i;

		/*
		 * The queue sizes and the pipe profiles both belong here.
		 * This used to memcpy a struct qos_shaper_conf over
		 * rte_sched_subport_params, which share no layout at all:
		 * the shaper starts with a 64-bit tb_rate and the subport
		 * params start with n_pipes_per_subport_enabled followed by
		 * the qsize array and a pipe_profiles pointer, so the rate
		 * was read as a pipe count and rate data as a pointer. The
		 * qsize array computed just below was then thrown away,
		 * which is what the __attribute__((unused)) on it was
		 * papering over.
		 */
		dpdk_params.n_pipes_per_subport_enabled =
			qinfo->port_params.n_pipes_per_subport;

		/*
		 * Queue sizes are indexed by DPDK's class number, so DANOS's
		 * last class has to be written at RTE_SCHED_TRAFFIC_CLASS_BE
		 * and not at its own index. Everything else stays zero, which
		 * is how DPDK marks a class as unused.
		 *
		 * Writing it at DANOS's index left the best-effort class with
		 * a queue size of 0, and DPDK silently dropped every packet
		 * classified into it -- the first three classes worked because
		 * their indices happen to coincide.
		 */
		for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
			dpdk_params.qsize[i] = 0;
		for (i = 0; i <= QOS_DANOS_TC_BE; i++)
			dpdk_params.qsize[qos_dpdk_tc_index(i)] =
				qos_dpdk_qsize(qos_sp_qsize_get(
					&qinfo->port_params, sinfo, i));

		dpdk_params.pipe_profiles = pipe_profiles;
		dpdk_params.n_pipe_profiles =
			qinfo->port_params.n_pipe_profiles;
		dpdk_params.n_max_pipe_profiles =
			qinfo->port_params.n_pipe_profiles;

		qos_copy_red_params(dpdk_red_params, sinfo);

		/*
		 * The fourth argument is the index into the port's subport
		 * profile table, which qos_dpdk_setup_params() fills one
		 * entry per subport.
		 */
		ret = rte_sched_subport_config(port, subport, &dpdk_params,
					       cfg);
		if (ret != 0) {
			DP_DEBUG(QOS_DP, ERR, DATAPLANE,
				 "Qos config subport %u failed: %d\n",
				 subport, ret);
			goto out_free_sched;
		}

		for (pipe = 0; pipe < qinfo->n_pipes; pipe++) {
			uint8_t profile = sinfo->profile_map[pipe];

			ret = rte_sched_pipe_config_v2(port, subport,
						       pipe, profile,
						       &dpdk_port_params);
			if  (ret != 0) {
				DP_DEBUG(QOS_DP, ERR, DATAPLANE,
					 "Qos config pipe subport %u pipe %u"
					 " profile %u failed: %d\n",
					 subport, pipe, profile, ret);
				goto out_free_sched;
			}
		}

		/* Update NPF rules */
		npf_cfg_commit_all();
	}

	/* Use RCU to set the pointer because changed by main thread
	 * but referenced by Tx thread
	 */
	DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,  "QoS on port %s enabled\n",
		 ifp->if_name);
	old_port = qinfo->dev_info.dpdk.port;
	rcu_assign_pointer(qinfo->dev_info.dpdk.port, port);
	defer_rcu(qos_dpdk_port_free_rcu, old_port);
	qos_dpdk_free_params(&dpdk_port_params);
	free(pipe_profiles);
	return 0;

 out_free_sched:
	rte_sched_port_free(port);
	qos_dpdk_free_params(&dpdk_port_params);
	free(pipe_profiles);
 out_disable_tx:
	ifp->qos_software_fwd = 0;
	disable_transmit_thread(ifp->if_port);
	return -1;
}

int qos_dpdk_stop(struct ifnet *ifp, struct sched_info *qinfo)
{
	struct rte_sched_port *port = qinfo->dev_info.dpdk.port;

	if (port == NULL)
		return 0; /* qos not started */

	rcu_assign_pointer(qinfo->dev_info.dpdk.port, NULL);
	defer_rcu(qos_dpdk_port_free_rcu, port);

	ifp->qos_software_fwd = 0;
	disable_transmit_thread(ifp->if_port);

	return 0;
}

/* Classify packet for QoS
 * Fixed mapping based on:
 *    VLAN  => subport
 *    NPF match => pipe
 *    DSCP   => traffic class
 *    hash    => queue
 * Non IP traffic, default to best effort and no flow
 */
static
int qos_npf_classify(struct ifnet *ifp, const struct sched_info *qinfo,
		     struct rte_mbuf **m)
{
	uint16_t ether_type = ethtype(*m, RTE_ETHER_TYPE_VLAN);
	uint32_t subport, pipe = 0, q = DEFAULT_Q;
	npf_result_t result = { .decision = NPF_DECISION_PASS };

	uint16_t vlan = pktmbuf_get_txvlanid(*m);

	if (vlan) {
		struct ifnet *vlan_ifp;

		vlan_ifp = if_vlan_lookup(ifp, vlan);
		if (vlan_ifp)
			ifp = vlan_ifp;
	}

	subport = qinfo->vlan_map[vlan];
	struct subport_info *sinfo = &qinfo->subport[subport];

	/* Do stateless classification */
	const struct npf_config *npf_config =
				rcu_dereference(sinfo->npf_config);

	if (npf_active(npf_config, NPF_QOS)) {
		result = npf_hook_notrack(npf_get_ruleset(npf_config,
					  NPF_RS_QOS), m, ifp, PFIL_OUT, 0,
					  ether_type, NULL);
		if (result.tag_set)
			pipe = result.tag;
	}

	if (pipe >= qinfo->n_pipes) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "NPF returned invalid tag %u, max-pipe:%u\n",
			 pipe, qinfo->n_pipes);
		return NPF_DECISION_BLOCK;
	}
	uint8_t profile = sinfo->profile_map[pipe];
	const struct queue_map *qmap = &qinfo->queue_map[profile];
	uint8_t pcp = pktmbuf_get_vlan_pcp(*m);
	uint8_t dscp = MAX_DSCP;

	/* Decide which queue to map to. Note that we only use the PCP map when
	 * the user hasn't configured a DSCP map but has configured a PCP map.
	 */
	if (qmap->local_priority &&
		ether_type == htons(RTE_ETHER_TYPE_ARP)) {
		q = qmap->local_priority_queue;
	} else if (vlan != 0 && !qmap->dscp_enabled && qmap->pcp_enabled) {
		q = qmap->pcp2q[pcp];
	} else {
		if (ether_type == htons(RTE_ETHER_TYPE_IPV4))
			dscp = ip_dscp_get(iphdr(*m));
		else if (ether_type == htons(RTE_ETHER_TYPE_IPV6))
			dscp = ip6_dscp_get(ip6hdr(*m));

		/*
		 * If DSCP was extracted we will either use the local high
		 * priority queue or a queue from the map.
		 * Otherwise, the default queue initialised above will be used.
		 */
		if (dscp < MAX_DSCP) {
			/*
			 * If this is a from-us packet with high enough
			 * priority, use the local priority queue if one
			 * is configured.
			 */
			if (qmap->local_priority &&
			    dscp >= (IPTOS_PREC_INTERNETCONTROL >> 2) &&
			    pktmbuf_mdata_exists(*m, PKT_MDATA_FROM_US))
				q = qmap->local_priority_queue;
			else
				q = qmap->dscp2q[dscp];
		}
	}

	rte_sched_port_pkt_write_v2(rcu_dereference(qinfo->dev_info.dpdk.port),
				 *m, subport, pipe,
				 qos_dpdk_tc(q), qos_dpdk_wrr(q),
				 RTE_COLOR_GREEN, dscp);
	return result.decision;
}

static int qos_classify(struct ifnet *ifp, struct sched_info *qinfo,
			struct rte_mbuf *enq_pkts[], uint32_t n_pkts)
{
	uint32_t i, j;

	/*
	 * Classify the packets to the Qos queues.
	 * NPF is run for classification to the pipe level
	 * so we need to check whether a packet has been
	 * dropped via policing and repack the array.
	 */
	for (i = j = 0; i < n_pkts; i++) {
		if (qos_npf_classify(ifp, qinfo,
				     &(enq_pkts[i])) == NPF_DECISION_BLOCK) {
			dp_pktmbuf_notify_and_free(enq_pkts[i]);
			continue;
		}

		/*
		 * Ensure session is cleared from pkts.
		 */
		pktmbuf_mdata_clear(enq_pkts[i], PKT_MDATA_SESSION_SENTRY);
		if (i != j)
			enq_pkts[j] = enq_pkts[i];
		j++;
	}
	return j;
}

/* Put/get packets currently ready to send from DPDK */
int qos_sched(struct ifnet *ifp, struct sched_info *qinfo,
	      struct rte_mbuf *enq_pkts[], uint32_t n_pkts,
	      struct rte_mbuf *deq_pkts[], uint32_t space)
{
	struct rte_sched_port *port =
		rcu_dereference(qinfo->dev_info.dpdk.port);

	if (unlikely(port == NULL)) {
		/* qos not started, because link down or race */
		pktmbuf_free_bulk(enq_pkts, n_pkts);
		return 0;
	}

	if (n_pkts > 0) {
		n_pkts = qos_classify(ifp, qinfo, enq_pkts, n_pkts);

		/*
		 * In case we've dropped the packets whilst policing
		 */
		if (n_pkts)
			rte_sched_port_enqueue(port, enq_pkts, n_pkts);
	}

	/* Get what is available to send */
	if (space > 0)
		return rte_sched_port_dequeue(port, deq_pkts, space);
	return 0;
}
