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

/* migrate all processes that we can migrate */
static int epm_remove(const krgnodemask_t *vector)
{
	struct task_struct *tsk;
	kerrighed_node_t dest_node = kerrighed_node_id;

	printk("epm_remove...\n");

	/* Here we assume that all nodes of the cluster are not removed */
	dest_node = krgnode_next_online_in_ring(dest_node);
	BUG_ON(__krgnode_isset(dest_node, vector));

	read_lock(&tasklist_lock);
	for_each_process(tsk) {
		if (!tsk->nsproxy->krg_ns)
			continue;

		if (cap_raised(tsk->krg_caps.effective, CAP_CAN_MIGRATE)) {
			/* have to migrate this process */
			printk("try to migrate %d %s to %d\n",
			       task_pid_knr(tsk), tsk->comm, dest_node);

			__migrate_linux_threads(tsk, MIGR_LOCAL_PROCESS,
						dest_node);

			/*
			 * Here we assume that all nodes of the cluster are not
			 * removed.
			 */
			dest_node = krgnode_next_online_in_ring(dest_node);
			BUG_ON(__krgnode_isset(dest_node, vector));

			continue;
		}

		if (cap_raised(tsk->krg_caps.effective, CAP_USE_REMOTE_MEMORY)) {
			/* have to kill this process */
			printk("epm_remove: have to kill %d (%s)\n",
			       task_pid_knr(tsk), tsk->comm);
			continue;
		}
	}
	read_unlock(&tasklist_lock);

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
	case HOTPLUG_NOTIFY_REMOVE:
		err = epm_remove(&ctx->node_set.v);
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
