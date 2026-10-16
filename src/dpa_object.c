/*
 * Copyright (c) 2026, i-danos.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "dpa_object.h"
#include "fal.h"
#include "fal_capability.h"
#include "if_var.h"
#include "ip_forward.h"
#include "nh_common.h"
#include "route_flags.h"
#include "json_writer.h"
#include "pd_show.h"

/*
 * The classes, and whether each can be walked.
 *
 * All ten can be walked. This table records, with the reason, any class that
 * cannot be -- the two QoS classes were in that position until they gained
 * walkers -- because something reconciling would read a class it cannot walk as
 * a class with nothing in it, then be confidently silent about every object in
 * it. A reader that cannot tell "absent" from "not carried" will read one as
 * the other.
 *
 * The six carry their backend in three different containers -- a struct for
 * routes, bitfields in the MPLS node, two named fields in the multicast
 * forwarding cache -- and all three take the value from pd_backend_for(), so
 * they cannot disagree about what to record. Which container a class happens
 * to use is not something a reader of this output should have to know.
 */
static const struct dpa_obj_class dpa_classes[] = {
	{ "route",  route_get_dpa_objects,  NULL },
	{ "route6", route6_get_dpa_objects, NULL },
	{ "mroute",     mroute_get_dpa_objects,  NULL },
	{ "mroute6",    mroute6_get_dpa_objects, NULL },
	{ "mpls-route", mpls_label_table_get_dpa_objects, NULL },
	{ "vrf",        vrf_get_dpa_objects,     NULL },
	{ "nexthop-group", nexthop_get_dpa_objects, NULL },
	{ "interface",  if_get_dpa_objects,      NULL },
	{ "qos-if",     qos_if_get_dpa_objects,   NULL },
	{ "qos-vlan",   qos_vlan_get_dpa_objects, NULL },
	{ NULL, NULL, NULL },
};

void dpa_object_emit_raw(json_writer_t *json, const char *class_name,
			 const char *key, enum pd_obj_state state,
			 uint16_t backend)
{
	jsonw_start_object(json);
	jsonw_string_field(json, "class", class_name);
	jsonw_string_field(json, "key", key);
	jsonw_string_field(json, "state", pd_obj_state_name(state));
	jsonw_string_field(json, "backend",
			   backend == PD_BACKEND_NONE ?
			   "sw-dataplane" : fal_backend_name(backend));
	jsonw_end_object(json);
}

void dpa_object_emit(json_writer_t *json, const char *class_name,
		     const char *key,
		     const struct pd_obj_state_and_flags *pd_state)
{
	dpa_object_emit_raw(json, class_name, key, pd_state->state,
			    pd_state->backend);
}

void dpa_object_start_owned(json_writer_t *json, const char *class_name,
			    const char *key,
			    const struct pd_obj_state_and_flags *pd_state,
			    bool owned)
{
	jsonw_start_object(json);
	jsonw_string_field(json, "class", class_name);
	jsonw_string_field(json, "key", key);
	jsonw_string_field(json, "state", pd_obj_state_name(pd_state->state));
	jsonw_string_field(json, "backend",
			   pd_state->backend == PD_BACKEND_NONE ?
			   "sw-dataplane" : fal_backend_name(pd_state->backend));
	/*
	 * Emitted always, not only when true. A field that appears only on
	 * some objects makes its absence ambiguous between "not owned" and
	 * "this producer does not report ownership", and a reader cannot tell
	 * those apart -- which is the same confusion the class list exists to
	 * prevent one level up.
	 */
	jsonw_bool_field(json, "dataplane_owned", owned);
}

void dpa_object_end(json_writer_t *json)
{
	jsonw_end_object(json);
}

void dpa_object_emit_owned(json_writer_t *json, const char *class_name,
			   const char *key,
			   const struct pd_obj_state_and_flags *pd_state,
			   bool owned)
{
	dpa_object_start_owned(json, class_name, key, pd_state, owned);
	dpa_object_end(json);
}

static const char *dpa_nh_kind(const struct next_hop *nh)
{
	if (nh->flags & RTF_BLACKHOLE)
		return "blackhole";
	if (nh->flags & (RTF_REJECT | RTF_NOROUTE))
		return "unreachable";
	if (nh->flags & RTF_LOCAL)
		return "local";
	if (nh->flags & RTF_SLOWPATH)
		return "non-dataplane interface";
	if (nh->flags & RTF_GATEWAY)
		return "gateway";
	return "directly connected";
}

void dpa_object_write_next_hops(json_writer_t *json, uint32_t nh_index,
				const struct next_hop_list *nextl, int af)
{
	unsigned int i;

	jsonw_uint_field(json, "nh_index", nh_index);
	/*
	 * Always an array, empty when the list is gone: a missing "next_hops"
	 * would read as "this producer does not report them", the ambiguity the
	 * ownership field above exists to avoid.
	 */
	jsonw_name(json, "next_hops");
	jsonw_start_array(json);
	for (i = 0; nextl && i < nextl->nsiblings; i++) {
		const struct next_hop *nh = nextl->siblings + i;
		const struct ifnet *ifp = dp_nh_get_ifp(nh);
		char buf[INET6_ADDRSTRLEN];

		jsonw_start_object(json);
		jsonw_string_field(json, "kind", dpa_nh_kind(nh));
		if (nh->flags & RTF_GATEWAY) {
			const void *a = af == AF_INET6 ?
				(const void *)&nh->gateway.address.ip_v6 :
				(const void *)&nh->gateway.address.ip_v4;

			if (inet_ntop(af, a, buf, sizeof(buf)))
				jsonw_string_field(json, "via", buf);
		}
		if (ifp)
			jsonw_string_field(json, "ifname", ifp->if_name);
		jsonw_bool_field(json, "dead", !!(nh->flags & RTF_DEAD));
		jsonw_bool_field(json, "backup", !!(nh->flags & RTF_BACKUP));
		jsonw_end_object(json);
	}
	jsonw_end_array(json);
}

static int dpa_object_show(FILE *f, const char *name, enum pd_obj_state subset)
{
	const struct dpa_obj_class *cls;
	json_writer_t *wr;
	bool matched = false;

	wr = jsonw_new(f);
	if (!wr)
		return -1;

	jsonw_name(wr, "dpa_objects");
	jsonw_start_object(wr);

	jsonw_name(wr, "classes");
	jsonw_start_array(wr);
	for (cls = dpa_classes; cls->name; ++cls) {
		if (name && strcmp(cls->name, name) != 0)
			continue;
		matched = true;
		jsonw_start_object(wr);
		jsonw_string_field(wr, "class", cls->name);
		jsonw_bool_field(wr, "enumerable", cls->enumerate != NULL);
		if (!cls->enumerate)
			jsonw_string_field(wr, "reason", cls->not_enumerable);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);

	jsonw_name(wr, "objects");
	jsonw_start_array(wr);
	for (cls = dpa_classes; cls->name; ++cls) {
		if (name && strcmp(cls->name, name) != 0)
			continue;
		if (cls->enumerate)
			cls->enumerate(wr, subset);
	}
	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	/*
	 * A class name nobody recognises is an error rather than an empty
	 * answer. An empty answer to a misspelt class is the most
	 * comfortable wrong result available here -- it looks exactly like a
	 * class with nothing in it.
	 */
	return matched ? 0 : -1;
}

/*
 * dpa object show [<class> [<state>]]
 */
int cmd_dpa(FILE *f, int argc, char **argv)
{
	const char *name = NULL;
	enum pd_obj_state subset = PD_OBJ_STATE_LAST;

	if (argc < 3)
		return -1;
	if (strcmp(argv[1], "object") != 0 || strcmp(argv[2], "show") != 0)
		return -1;

	if (argc >= 4)
		name = argv[3];
	if (argc >= 5) {
		subset = pd_obj_state_from_name(argv[4]);
		if (subset == PD_OBJ_STATE_LAST)
			return -1;
	}

	return dpa_object_show(f, name, subset);
}
