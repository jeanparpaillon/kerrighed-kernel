/*
 *  Copyright (C) 2009, Matthieu Fertré, Kerlabs.
 */
#include <linux/cluster_barrier.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/semaphore.h>
#include <kddm/kddm_flush_object.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/hotplug.h>
#include "util.h"
#include "ipc_handler.h"
#include "msg_handler.h"
#include "shm_handler.h"
#include "sem_handler.h"
#include "krgmsg.h"

static struct cluster_barrier *barrier;
DECLARE_RWSEM(krgipcmsg_rwsem);

static int ipc_remove_local(struct hotplug_context *ctx)
{
	int err;
	struct ipc_namespace *ns;
	krgnodemask_t nodes;
	kerrighed_node_t master;

	printk("ipc_remove_local...\n");

	down_write(&krgipcmsg_rwsem);

	krgnodes_or(nodes, ctx->node_set.v, krgnode_online_map);
	master = first_krgnode(nodes);

	err = cluster_barrier(barrier, &nodes, master);
	if (err)
		goto out;

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	err = krg_msg_flush_set(ns);
	BUG_ON(err);

	err = krg_shm_flush_set(ns);
	BUG_ON(err);

	err = krg_sem_flush_set(ns);
	BUG_ON(err);

	put_ipc_ns(ns);

	err = cluster_barrier(barrier, &nodes, master);

out:
	up_write(&krgipcmsg_rwsem);

	return err;
}

static int ipc_remove_advert(struct hotplug_context *ctx)
{
	int err;
	krgnodemask_t nodes;

	printk("ipc_remove_advert...\n");

	down_write(&krgipcmsg_rwsem);

	krgnodes_or(nodes, ctx->node_set.v, krgnode_online_map);

	err = cluster_barrier(barrier, &nodes,
			      first_krgnode(nodes));
	if (err)
		goto out;

	/* wait for objects to be flushed */

	err = cluster_barrier(barrier, &nodes,
			      first_krgnode(nodes));

	up_write(&krgipcmsg_rwsem);
out:
	return err;
}

static int ipc_notification(struct notifier_block *nb, hotplug_event_t event,
			    void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch(event){
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = ipc_remove_local(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		err = ipc_remove_advert(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int ipc_hotplug_init(void)
{
	int err = 0;

	barrier = alloc_cluster_barrier(IPC_HOTPLUG_BARRIER);
	if (IS_ERR(barrier)) {
		err = PTR_ERR(barrier);
		goto err_barrier;
	}

	register_hotplug_notifier(ipc_notification, HOTPLUG_PRIO_IPC);

err_barrier:
	return err;
}

void ipc_hotplug_cleanup(void)
{
	free_cluster_barrier(barrier);
}
