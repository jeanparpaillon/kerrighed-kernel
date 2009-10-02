/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/uaccess.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>

#include "hotplug_internal.h"

int __nodes_add(struct hotplug_node_set *nodes_set)
{
	kerrighed_subsession_id = nodes_set->subclusterid;

	hotplug_add_notify(nodes_set, HOTPLUG_NOTIFY_ADD);

	return 0;
}

static void handle_node_add(struct rpc_desc *rpc_desc, void *data, size_t size)
{
	__nodes_add(data);
}

static int do_nodes_add(const struct hotplug_node_set *node_set)
{
	kerrighed_node_t node;
	struct hotplug_node_set node_set_tmp;

	node_set_tmp = *node_set;

	/* Send request to all members of the current cluster */
	for_each_online_krgnode(node){

		krgnode_set(node, node_set_tmp.v);

		printk("send a NODE_ADD to %d\n", node);
		rpc_async(NODE_ADD, node,
				node_set, sizeof(*node_set));

	}

	/*
	 * Send request to all new members
	 * Current limitation: only not-started nodes can be added to a
	 * running cluster (ie: a node can't move from a subcluster to another one)
	 */
	rpc_async_m(CLUSTER_START, &node_set->v,
			&node_set_tmp, sizeof(node_set_tmp));

	return 0;
}

static int nodes_add(void __user *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	int err;

	if (copy_from_user(&__node_set, arg, sizeof(struct __hotplug_node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;
	err = krgnodemask_copy_from_user(&node_set.v, &__node_set.v);
	if (err)
		return err;

	if (node_set.subclusterid != kerrighed_subsession_id)
		return -EPERM;

	if (!krgnode_online(kerrighed_node_id))
		return -EPERM;

	if (!krgnodes_subset(node_set.v, krgnode_present_map))
		return -ENONET;

	if (krgnodes_intersects(node_set.v, krgnode_online_map))
		return -EPERM;

	return do_nodes_add(&node_set);
}

int hotplug_add_init(void)
{
	rpc_register_void(NODE_ADD, handle_node_add, 0);

	register_proc_service(KSYS_HOTPLUG_ADD, nodes_add);
	return 0;
}

void hotplug_add_cleanup(void)
{
}
