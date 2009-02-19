/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <kerrighed/hashtable.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgflags.h>
#include <asm/uaccess.h>
#include <asm/ioctl.h>

#include <tools/workqueue.h>
#include <tools/krg_syscalls.h>
#include <tools/krg_services.h>
#include <rpc/rpc.h>

#include "hotplug.h"
#include "hotplug_internal.h"

inline
void do_local_node_remove(struct hotplug_node_set *node_set)
{
	kerrighed_node_t node;

	SET_KERRIGHED_NODE_FLAGS(KRGFLAGS_STOPPING);
	printk("do_local_node_remove\n");

	printk("...notify local\n");
	hotplug_remove_notify(node_set, HOTPLUG_NOTIFY_REMOVE_LOCAL);
	printk("...notify_distant\n");
	hotplug_remove_notify(node_set, HOTPLUG_NOTIFY_REMOVE_DISTANT);

	printk("...confirm\n");
	rpc_sync_m(NODE_REMOVE_CONFIRM, &krgnode_online_map, node_set, sizeof(*node_set));

	CLEAR_KERRIGHED_NODE_FLAGS(KRGFLAGS_RUNNING);

	for_each_online_krgnode(node)
		if(node != kerrighed_node_id)
			clear_krgnode_online(node);

	hooks_stop();
	SET_KERRIGHED_NODE_FLAGS(KRGFLAGS_STOPPED);

#if 0
	printk("...sleep\n");
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(10*HZ);

	printk("...try to reboot\n");
	queue_work(krg_nb_wq, &fail_work);
#endif
}

inline
void do_other_node_remove(struct hotplug_node_set *node_set)
{
	printk("do_other_node_remove\n");
	hotplug_remove_notify(node_set, HOTPLUG_NOTIFY_REMOVE_ADVERT);
	rpc_async_m(NODE_REMOVE_ACK, &node_set->v, NULL, 0);				
}

static void handle_node_remove(struct rpc_desc *desc, void *data, size_t size)
{
	struct hotplug_node_set *node_set;

	printk("handle_node_remove\n");
	node_set = data;

	if(!krgnode_isset(kerrighed_node_id, node_set->v)){
		do_other_node_remove(node_set);
		return;
	}

	do_local_node_remove(node_set);
}

/* we receive the ack from cluster about our remove operation */
static void handle_node_remove_ack(struct rpc_desc *desc, void *data, size_t size)
{
	printk("Need to take care that node %d ack the remove (if needed)\n", desc->client);
}

/* cluster receive the confirmation about the remove operation */
static int handle_node_remove_confirm(struct rpc_desc *desc, void *data, size_t size)
{
	if(desc->client==kerrighed_node_id)
		return 0;
	
	hotplug_remove_notify((void*)&desc->client, HOTPLUG_NOTIFY_REMOVE_ACK);
	printk("Kerrighed: node %d removed\n", desc->client);
	return 0;
}

inline void __fwd_remove_cb(struct hotplug_node_set *node_set)
{
	printk("__fwd_remove_cb: begin (%d / %d)\n", node_set->subclusterid, kerrighed_subsession_id);
	if (node_set->subclusterid == kerrighed_subsession_id) {

		rpc_async_m(NODE_REMOVE, &krgnode_online_map, node_set, sizeof(*node_set));
		
	} else {
		kerrighed_node_t node;

		printk("__fwd_remove_cb: m1\n");
		node = 0;
		while ((universe[node].subid != node_set->subclusterid)
		       && (node < KERRIGHED_MAX_NODES))
			node++;
		printk("__fwd_remove_cb: m2 (%d/%d)\n", node, KERRIGHED_MAX_NODES);

		if (node == KERRIGHED_MAX_NODES) {
			BUG();
			printk
			    ("WARNING: here we have no idea... may be the next one will be more luky!\n");
			node = kerrighed_node_id + 1;
		}

		printk("send a NODE_FWD_REMOVE to %d\n", node);
		rpc_async(NODE_FWD_REMOVE, node, node_set, sizeof(*node_set));
	}
}

static void handle_node_fwd_remove(struct rpc_desc *desc, void *data, size_t size)
{
	__fwd_remove_cb(data);
}

static inline int __clean_node_set(krgnodemask_t *nodes)
{
	kerrighed_node_t node;
	int r = 0; /* false */

	/* can't leave a cluster by myself */
	krgnode_clear(kerrighed_node_id, *nodes);

	__for_each_krgnode_mask(node, nodes){
		if (!krgnode_possible(node)) {
			printk("Node %d is not in the cluster\n", node);
			krgnode_clear(node, *nodes);
		} else {
			/* there is at least one valid node */
			r = 1;
		}
	}
	return r;
}

static int nodes_remove(void *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;

	if (copy_from_user(&__node_set, arg, sizeof(struct __hotplug_node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;
	if (krgnodemask_copy_from_user(&node_set.v, &__node_set.v))
		return -EFAULT;

	if (!__clean_node_set(&node_set.v))
		return -ENONET;

	__fwd_remove_cb(&node_set);
	return 0;
}

static void handle_node_poweroff(struct rpc_desc *desc)
{
	emergency_sync();
	emergency_remount();

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(5 * HZ);

	local_irq_enable();
	kernel_power_off();

	// should never be reached
	BUG();

}

static int nodes_poweroff(void *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	int unused;
	
	if (copy_from_user(&__node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;

	if (krgnodemask_copy_from_user(&node_set.v, &__node_set.v))
		return -EFAULT;

	rpc_async_m(NODE_POWEROFF, &node_set.v,
		    &unused, sizeof(unused));
	
	return 0;
}

/* Currently unused... Commented to avoid compilation warning.
static void handle_node_reboot(struct rpc_desc *desc, void *data, size_t size)
{
	emergency_sync();
	emergency_remount();

	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(5 * HZ);

	local_irq_enable();
	machine_restart(NULL);

	// should never be reached
	BUG();

}
*/

static int nodes_reboot(void *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	int unused;
	
	if (copy_from_user(&__node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;
	
	if (krgnodemask_copy_from_user(&node_set.v, &__node_set.v))
		return -EFAULT;

	rpc_async_m(NODE_REBOOT, &node_set.v,
		    &unused, sizeof(unused));
	
	return 0;
}


int hotplug_remove_init(void)
{
	rpc_register(NODE_POWEROFF, handle_node_poweroff, 0);
	rpc_register_void(NODE_REMOVE, handle_node_remove, 0);
	rpc_register_void(NODE_REMOVE_ACK, handle_node_remove_ack, 0);
	rpc_register_void(NODE_FWD_REMOVE, handle_node_fwd_remove, 0);
	rpc_register_int(NODE_REMOVE_CONFIRM, handle_node_remove_confirm, 0);
	
	register_proc_service(KSYS_HOTPLUG_REMOVE, nodes_remove);
	register_proc_service(KSYS_HOTPLUG_POWEROFF, nodes_poweroff);
	register_proc_service(KSYS_HOTPLUG_REBOOT, nodes_reboot);

	return 0;
}

void hotplug_remove_cleanup(void)
{
}
