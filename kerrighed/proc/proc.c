/*
 *  kerrighed/proc/proc.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include <kerrighed/hotplug.h>

#include "proc_internal.h"

static int proc_notification(struct notifier_block *nb, hotplug_event_t event,
			     void *data)
{
#ifndef CONFIG_KRG_EPM
	struct hotplug_context *ctx = data;
#endif

	switch (event) {
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
#ifndef CONFIG_KRG_EPM
		zap_local_krg_ns_processes(ctx->ns, EXIT_DEAD);
#endif
		proc_task_remove_local();
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

/** Initial function of the module
 *  @author Geoffroy Vallee, Pascal Gallard
 */
int init_proc(void)
{
	printk("Proc initialisation: start\n");

	if (register_hotplug_notifier(proc_notification, HOTPLUG_PRIO_PROC))
		panic("kerrighed: Couldn't register PROC hotplug notifier!\n");

	proc_task_start();
	proc_krg_exit_start();

	proc_remote_syscalls_start();
	register_remote_syscalls_hooks();

	printk("Proc initialisation: done\n");

	return 0;
}

void cleanup_proc(void)
{
}
