/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 *  Copyright (C) 2009, Louis Rilling, Kerlabs.
 */
#include <linux/notifier.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>
#include <kddm/kddm.h>

#include <kerrighed/dynamic_node_info_linker.h>
#include "static_node_info_linker.h"
#include "dynamic_cpu_info_linker.h"
#include "static_cpu_info_linker.h"
#include "proc.h"

struct notifier_block;

static void procfs_add(krgnodemask_t *v)
{
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, v)
		create_proc_node_info(i);
}

static int procfs_remove_other_node(kerrighed_node_t node)
{
	krg_static_node_info_t *info;
	int err;

	remove_proc_node_info(node);

	/*
	 * In order to avoid destroying the removed node's procfs KDDM objects,
	 * All other nodes destroy their copies.
	 */
	info = get_static_node_info(node);
	for (i = 0; i < info->nr_cpu; i++) {
		err = _kddm_flush_object(static_cpu_info_kddm_set,
					 __krg_cpu_id(node, i),
					 node);
		if (err)
			return err;
		err = _kddm_flush_object(dynamic_cpu_info_kddm_set,
					 __krg_cpu_id(node, i),
					 node);
		if (err)
			return err;
	}
	err = _kddm_flush_object(static_node_info_kddm_set, node, node);
	if (err)
		return err;
	err = _kddm_flush_object(dynamic_node_info_kddm_set, node, node);

	return err;
}

static int procfs_remove_local(krgnodemask_t *v)
{
	krgnodemask_t other_nodes;
	kerrighed_node_t node;

	krgnodes_or(other_nodes, krgnode_online_map, *v);
	krgnode_clear(kerrighed_node_id, other_nodes);
	for_each_krgnode_mask(node, other_nodes)
		procfs_remove_other_node(node);

	remove_proc_node_info(kerrighed_node_id);
}

static void procfs_remove_advert(krgnodemask_t *v)
{
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, v)
		procfs_remove_other_node(i);
}

static int procfs_notification(struct notifier_block *nb, hotplug_event_t event,
			       void *data)
{
	struct hotplug_context *ctx = data;

	switch (event) {
	case HOTPLUG_NOTIFY_ADD:
		procfs_add(&ctx->node_set.v);
		break;
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		procfs_remove_local(&ctx->node_set.v);
		break;
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		procfs_remove_advert(&ctx->node_set.v);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

int procfs_hotplug_init(void)
{
	register_hotplug_notifier(procfs_notification,
				  HOTPLUG_PRIO_MEMBERSHIP_PROCFS);
	return 0;
}

void procfs_hotplug_cleanup(void)
{
}
