/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <asm/uaccess.h>
#include <asm/ioctl.h>
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

inline void __fwd_add_cb(struct hotplug_node_set *node_set)
{
	if (node_set->subclusterid == kerrighed_subsession_id) {
		kerrighed_node_t node;
		struct hotplug_node_set node_set_tmp;

		node_set_tmp = *node_set;

		// send request to all the members in the current cluster
		for_each_online_krgnode(node){

			krgnode_set(node, node_set_tmp.v);

			printk("send a NODE_ADD to %d\n", node);
			rpc_async(NODE_ADD, node,
				  node_set, sizeof(*node_set));

		}

		// send request to all new members
		// Current limitation: only not-started nodes can be added to a
		// running cluster (ie: a node can't move from a subcluster to another one)
		rpc_async_m(CLUSTER_START, &node_set->v,
			    &node_set_tmp, sizeof(node_set_tmp));

	} else {
		kerrighed_node_t node;

		node = 0;
		while ((universe[node].subid != node_set->subclusterid)
		       && (node < KERRIGHED_MAX_NODES))
			node++;

		if (node == KERRIGHED_MAX_NODES) {
			BUG();
			printk
			    ("WARNING: here we have no idea... may be the next one will be more luky!\n");
			node = kerrighed_node_id + 1;
		}

		printk("send a NODE_FWD_ADD to %d\n", node);
		rpc_async(NODE_FWD_ADD, node, node_set, sizeof(*node_set));
	}
}

static void handle_node_fwd_add(struct rpc_desc *desc, void *data, size_t size)
{
	__fwd_add_cb(data);
}

inline int __clean_node_set(krgnodemask_t *nodes)
{
	kerrighed_node_t node;
	int r = 0; /* false */

	/* can't join a cluster by myself */
	krgnode_clear(kerrighed_node_id, *nodes);

	__for_each_krgnode_mask(node, nodes){
		if (!krgnode_present(node)) {
			printk("Node %d is not on the network\n", node);
			krgnode_clear(node, *nodes);
		} else {
			/* there is at least one valid node */
			r = 1;
		}
	}
	return r;
}

static int nodes_add(void *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;

	if (copy_from_user(&__node_set, arg, sizeof(struct __hotplug_node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;
	if (krgnodemask_copy_from_user(&node_set.v, &__node_set.v))
		return -ENONET;

	if (!__clean_node_set(&node_set.v))
		return -ENONET;

	__fwd_add_cb(&node_set);
	return 0;
}

int hotplug_add_init(void)
{
	rpc_register_void(NODE_ADD, handle_node_add, 0);
	rpc_register_void(NODE_FWD_ADD, handle_node_fwd_add, 0);

	register_proc_service(KSYS_HOTPLUG_ADD, nodes_add);
	return 0;
}

void hotplug_add_cleanup(void)
{
}
