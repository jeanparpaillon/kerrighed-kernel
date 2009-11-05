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
#include <kerrighed/migration.h>
#include "pid.h"

static int epm_add(struct hotplug_context *ctx)
{
	return pidmap_map_add(ctx);
}

/* Try to migrate all processes to remaining nodes */
static void expell_all(struct hotplug_context *ctx)
{
	struct task_struct *tsk;
	kerrighed_node_t target;
	int nr = 0, nr_cpus;

	target = krgnode_next_online_in_ring(kerrighed_node_id);

	rcu_read_lock();
	for_each_process(tsk) {
		if (tsk->nsproxy->krg_ns != ctx->ns)
			continue;

		printk("try to migrate %d %s to %d\n",
		       task_pid_knr(tsk), tsk->comm, target);
		if (!__migrate_linux_threads(tsk, MIGR_LOCAL_PROCESS, target)) {
			nr++;
			target = krgnode_next_online_in_ring(target);
		}
	}
	rcu_read_unlock();

	if (nr) {
		/* Give time to tasks to start migrating */
		__set_current_state(TASK_UNINTERRUPTIBLE);
		nr_cpus = num_online_cpus();
		schedule_timeout((nr * HZ + nr_cpus - 1) / nr_cpus);
	}
}

static int epm_remove_local(struct hotplug_context *ctx)
{
	printk("epm_remove...\n");

	if (num_online_krgnodes())
		expell_all(ctx);

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
