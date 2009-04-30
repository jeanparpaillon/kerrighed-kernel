/*
 *  kerrighed/proc/krg_exit.c
 *
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/personality.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <kerrighed/task.h>

#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/task.h>
#include <kerrighed/krg_exit.h>

static void *kh_release_task;

void krg_release_task(struct task_struct *p)
{
	if (!kh_release_task)
		return;

		krg_task_free(p);
}

void register_krg_exit_hooks(void)
{
	hook_register(&kh_release_task, (void *)true);
}

/**
 * @author Pascal Gallard, Louis Rilling
 */
void proc_krg_exit_start(void)
{
}

/**
 * @author Pascal Gallard, Louis Rilling
 */
void proc_krg_exit_exit(void)
{
}
