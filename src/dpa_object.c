/*
 * Copyright (c) 2026, i-danos.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>

#include "dpa_object.h"
#include "fal.h"
#include "fal_capability.h"
#include "json_writer.h"
#include "pd_show.h"

/*
 * The classes, and whether each can be walked.
 *
 * route and route6 can, and are the two that carry a per-object backend --
 * they hold a struct pd_obj_state_and_flags, where the others keep a bare
 * enum pd_obj_state with nowhere to record which backend took the object.
 * Saying so here, rather than emitting those classes with the backend quietly
 * missing, is the same distinction the header argues for: a reader that cannot
 * tell "absent" from "not carried" will read one as the other.
 */
static const struct dpa_obj_class dpa_classes[] = {
	{ "route",  route_get_dpa_objects,  NULL },
	{ "route6", route6_get_dpa_objects, NULL },
	{ "mroute",     NULL,
	  "walker exists; object keeps a bare pd_obj_state with no backend" },
	{ "mroute6",    NULL,
	  "walker exists; object keeps a bare pd_obj_state with no backend" },
	{ "mpls-route", NULL,
	  "walker exists; object keeps a bare pd_obj_state with no backend" },
	{ "vrf",        NULL,
	  "walker exists; object keeps a bare pd_obj_state with no backend" },
	{ "qos-if",     NULL, "no walker" },
	{ "qos-vlan",   NULL, "no walker" },
	{ NULL, NULL, NULL },
};

void dpa_object_emit(json_writer_t *json, const char *class_name,
		     const char *key,
		     const struct pd_obj_state_and_flags *pd_state)
{
	jsonw_start_object(json);
	jsonw_string_field(json, "class", class_name);
	jsonw_string_field(json, "key", key);
	jsonw_string_field(json, "state", pd_obj_state_name(pd_state->state));
	jsonw_string_field(json, "backend",
			   pd_state->backend == PD_BACKEND_NONE ?
			   "sw-dataplane" : fal_backend_name(pd_state->backend));
	jsonw_end_object(json);
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
