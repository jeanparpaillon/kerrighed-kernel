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
	int i, err;

	/*
	 * Do not keep copies of remaining nodes' procfs KDDM objects
	 * Nodes being removed globally destroy their objects.
	 */
	info = get_static_node_info(node);
	for (i = 0; i < info->nr_cpu; i++) {
		err = _kddm_flush_object(static_cpu_info_kddm_set,
					 __krg_cpu_id(node, i),
					 node);
		if (err && err != -ENOENT)
			return err;

		err = _kddm_flush_object(dynamic_cpu_info_kddm_set,
					 __krg_cpu_id(node, i),
					 node);
		if (err && err != -ENOENT)
			return err;
	}

	err = _kddm_flush_object(static_node_info_kddm_set, node, node);
	if (err && err != -ENOENT)
		return err;

	err = _kddm_flush_object(dynamic_node_info_kddm_set, node, node);
	if (err == -ENOENT)
		err = 0;
	return err;
}

static int procfs_remove_local_node(void)
{
	int i, err;

	for_each_online_cpu(i) {
		err = _kddm_remove_object(static_cpu_info_kddm_set,
					  krg_cpu_id(i));
		if (err && err != -ENOENT)
			return err;

		err = _kddm_remove_object(dynamic_cpu_info_kddm_set,
					  krg_cpu_id(i));
		if (err && err != -ENOENT)
			return err;
	}
	init_static_cpu_info_objects();
	init_dynamic_cpu_info_objects();

	err = _kddm_remove_object(static_node_info_kddm_set,
				  kerrighed_node_id);
	if (err && err != -ENOENT)
		return err;
	init_static_node_info_object();

	err = _kddm_remove_object(dynamic_node_info_kddm_set,
				  kerrighed_node_id);
	if (err && err != -ENOENT)
		return err;
	init_dynamic_node_info_object();

	return 0;
}

static int procfs_remove_local(krgnodemask_t *v)
{
	krgnodemask_t all_nodes;
	kerrighed_node_t node;
	int err;

	krgnodes_or(all_nodes, krgnode_online_map, *v);
	for_each_krgnode_mask(node, all_nodes)
		remove_proc_node_info(node);

	for_each_online_krgnode(node) {
		err = procfs_remove_other_node(node);
		if (err)
			return err;
	}
	return procfs_remove_local_node();
}

static int procfs_remove_advert(krgnodemask_t *v)
{
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, v)
		remove_proc_node_info(i);

	return 0;
}

static int procfs_notification(struct notifier_block *nb, hotplug_event_t event,
			       void *data)
{
	struct hotplug_context *ctx = data;
	int err = 0;

	switch (event) {
	case HOTPLUG_NOTIFY_ADD:
		procfs_add(&ctx->node_set.v);
		break;
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = procfs_remove_local(&ctx->node_set.v);
		break;
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		err = procfs_remove_advert(&ctx->node_set.v);
		break;
	default:
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int procfs_hotplug_init(void)
{
	register_hotplug_notifier(procfs_notification, HOTPLUG_PRIO_PROCFS);
	return 0;
}

void procfs_hotplug_cleanup(void)
{
}
