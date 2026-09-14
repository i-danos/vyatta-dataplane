/*
 * Copyright (c) 2026, i-danos.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef DPA_OBJECT_H
#define DPA_OBJECT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "json_writer.h"
#include "pd_show.h"

/*
 * One shape for every forwarding object, whatever class it belongs to.
 *
 * "pd show dataplane" reports per class: counters in the class's own terms and,
 * for the classes that have a walker, a dump in the class's own shape. That is
 * the right view for a person looking at routes. It is the wrong view for
 * anything that has to compare what is programmed against what was asked for,
 * because such a thing would have to know every class's private shape, and
 * would silently learn nothing about a class it had not been taught.
 *
 * So: class, key, state, backend. Four fields, the same four for every object.
 *
 * The key is meant to be compared, not parsed for display. It carries the
 * identity a Desired side would use for the same object -- the external VRF id
 * rather than the internal one, because that is the number FRR and an operator
 * both say.
 *
 * Two Desired sides, which is worth stating because it is not obvious and it
 * shapes everything above this layer: configuration objects come from configd,
 * and routes do not. zebra runs with -M dplane_fpm_nl, so a route's desired
 * form lives in FRR's RIB and arrives over FPM. A reconciliation loop for
 * routes therefore compares against zebra, not against the configuration.
 */

/*
 * Whether a class can be walked at all.
 *
 * "no objects" and "cannot enumerate" are different answers and the difference
 * matters more here than anywhere else: something reconciling would treat a
 * class it cannot walk as a class with nothing in it, and would then be
 * confidently silent about every object in it. The class list says which is
 * which rather than leaving it to be inferred from an empty array.
 */
struct dpa_obj_class {
	const char *name;
	int (*enumerate)(json_writer_t *json, enum pd_obj_state subset);
	/* Why not, for a class that cannot be walked yet. */
	const char *not_enumerable;
};

/*
 * Emit one object whose state and backend are not carried in a
 * struct pd_obj_state_and_flags -- the MPLS label table packs them into
 * bitfields, and the multicast forwarding cache keeps them as two named
 * fields. Same four output fields either way; the caller having a different
 * container is not something a reader should have to know about.
 */
void dpa_object_emit_raw(json_writer_t *json, const char *class_name,
			 const char *key, enum pd_obj_state state,
			 uint16_t backend);

/*
 * Emit one object in the uniform shape.
 *
 * `owned` marks an object the data plane created for itself rather than one it
 * was told about. Those exist in the forwarding table and correctly have no
 * counterpart upstream, so anything comparing the two sides has to be able to
 * tell them from objects that went missing -- otherwise a reconciliation loop
 * would try to "repair" 127.0.0.0/8 by asking zebra for a route zebra was
 * never going to have.
 *
 * The data plane already knows which these are: reserved_routes[] and
 * rt_is_reserved() in route.c, the same in route_v6.c. The classification is
 * not invented here, it is carried out to where a reader can see it. Putting
 * the discriminator in the data is the point -- the alternative is a comparison
 * tool holding a list of prefixes it believes are special, which is a copy of
 * this table that nothing keeps in step with it.
 */
void dpa_object_emit_owned(json_writer_t *json, const char *class_name,
			   const char *key,
			   const struct pd_obj_state_and_flags *pd_state,
			   bool owned);

void dpa_object_emit(json_writer_t *json, const char *class_name,
		     const char *key,
		     const struct pd_obj_state_and_flags *pd_state);

/* "dpa object show [<class>] [<state>]" */
int cmd_dpa(FILE *f, int argc, char **argv);

/* Per-class enumeration, uniform shape. */
int route_get_dpa_objects(json_writer_t *json, enum pd_obj_state subset);
int route6_get_dpa_objects(json_writer_t *json, enum pd_obj_state subset);
int vrf_get_dpa_objects(json_writer_t *json, enum pd_obj_state subset);
int mpls_label_table_get_dpa_objects(json_writer_t *json,
				     enum pd_obj_state subset);
int mroute_get_dpa_objects(json_writer_t *json, enum pd_obj_state subset);
int mroute6_get_dpa_objects(json_writer_t *json, enum pd_obj_state subset);

#endif /* DPA_OBJECT_H */
