/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <kerrighed/capabilities.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <kerrighed/pid.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/namespace.h>
#include <kerrighed/migration.h>
#include <kerrighed/action.h>

#include "epm_internal.h"

#define MIGRATION_BATCH_SIZE 10

static int epm_add(struct hotplug_context *ctx)
{
	return pidmap_map_add(ctx);
}

/* Try to migrate all processes to remaining nodes */
static void expel_all(struct hotplug_context *ctx)
{
	struct task_struct *tsk, *tmp;
	struct migration_wait wait;
	kerrighed_node_t target;
	int err;

	target = krgnode_next_online_in_ring(kerrighed_node_id);
	read_lock(&tasklist_lock);
	for_each_process(tsk) {
		if (task_active_pid_ns(tsk)->krg_ns != ctx->ns)
			continue;

		/* Migration in progress or finished? */
		if (krg_action_pending(tsk, EPM_MIGRATE)
		    || (tsk->flags & PF_AWAY))
			continue;

		printk("try to migrate %d %s to %d\n",
		       task_pid_knr(tsk), tsk->comm, target);
		err = __migrate_linux_threads(tsk, MIGR_LOCAL_PROCESS, target);
		if (err) {
			printk("failed to migrate %d %s (err = %d)! Stopping it.\n",
			       task_pid_knr(tsk), tsk->comm, err);
			group_send_sig_info(SIGSTOP, SEND_SIG_FORCED, tsk);
			continue;
		}

		target = krgnode_next_online_in_ring(target);
	}
	read_unlock(&tasklist_lock);

	/* Wait for migrations to finish */
	for (;;) {
		tsk = NULL;
		read_lock(&tasklist_lock);
		for_each_process(tmp) {
			if (task_active_pid_ns(tmp)->krg_ns != ctx->ns)
				continue;

			if (!krg_action_pending(tmp, EPM_MIGRATE))
				continue;

			tsk = tmp;
			get_task_struct(tsk);
			break;
		}
		read_unlock(&tasklist_lock);

		if (!tsk)
			break;

		prepare_wait_for_migration(tsk, &wait);
		err = wait_for_migration(tsk, &wait);
		if (err || !(tsk->flags & PF_AWAY))
			printk("failed to migrate %d %s (err = %d)!\n",
			       task_pid_knr(tsk), tsk->comm, err);
		finish_wait_for_migration(&wait);

		put_task_struct(tsk);
	}

	read_lock(&tasklist_lock);
	for_each_process(tsk) {
		if (task_active_pid_ns(tsk)->krg_ns != ctx->ns)
			continue;

		if (!(tsk->flags & PF_AWAY))
			printk("failed to migrate %d %s! Resuming it.\n",
			       task_pid_knr(tsk), tsk->comm);
		group_send_sig_info(SIGCONT, SEND_SIG_FORCED, tsk);
	}
	read_unlock(&tasklist_lock);
}

static int epm_remove_local(struct hotplug_context *ctx)
{
	printk("epm_remove...\n");

	if (num_online_krgnodes()) {
		expel_all(ctx);
		zap_local_krg_ns_processes(ctx->ns, EXIT_ZOMBIE);
		expel_all(ctx);
	}

	zap_local_krg_ns_processes(ctx->ns, EXIT_DEAD);

	application_remove_local();
	children_remove_local();
	signal_remove_local();
	sighand_remove_local();
	pidmap_map_remove_local(ctx);
	pid_remove_local();

	return 0;
}

static int epm_notification(struct notifier_block *nb, hotplug_event_t event,
			    void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		err = epm_add(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = epm_remove_local(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int epm_hotplug_init(void)
{
	register_hotplug_notifier(epm_notification, HOTPLUG_PRIO_EPM);
	return 0;
}

void epm_hotplug_cleanup(void)
{
}
