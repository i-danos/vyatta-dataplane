/*
 * Copyright (c) 2026, DANOS / Vyatta DataPlane Project.
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Built-in Pure Software FAL (Forwarding Abstraction Layer) Engine
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "compiler.h"
#include "fal.h"
#include "fal_plugin.h"
#include "vplane_log.h"
#include "vplane_debug.h"

static void fal_sw_sys_cleanup(void)
{
	RTE_LOG(INFO, DATAPLANE, "Cleaned up Pure Software FAL Engine\n");
}

static struct fal_sys_ops fal_sw_sys_ops = {
	.cleanup = fal_sw_sys_cleanup,
};

static struct message_handler fal_sw_handler = {
	.sys = &fal_sw_sys_ops,
};

void fal_sw_init(void)
{
	if (!fal_plugins_present()) {
		fal_register_message_handler(&fal_sw_handler);
		RTE_LOG(INFO, DATAPLANE, "Registered Built-in Pure Software FAL Provider\n");
	}
}
