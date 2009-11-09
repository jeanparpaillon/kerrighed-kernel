/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgflags.h>
#include <kerrighed/workqueue.h>
#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>

#include "hotplug_internal.h"

static void do_local_node_remove(struct hotplug_node_set *node_set)
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

static void do_other_node_remove(struct hotplug_node_set *node_set)
{
	printk("do_other_node_remove\n");
	hotplug_remove_notify(node_set, HOTPLUG_NOTIFY_REMOVE_ADVERT);
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

/* cluster receive the confirmation about the remove operation */
static int handle_node_remove_confirm(struct rpc_desc *desc, void *data, size_t size)
{
	if(desc->client==kerrighed_node_id)
		return 0;

	hotplug_remove_notify((void*)&desc->client, HOTPLUG_NOTIFY_REMOVE_ACK);
	printk("Kerrighed: node %d removed\n", desc->client);
	return 0;
}

static int do_nodes_remove(struct hotplug_node_set *node_set)
{
	return rpc_async_m(NODE_REMOVE, &krgnode_online_map,
			   node_set, sizeof(*node_set));
}

static int nodes_remove(void __user *arg)
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

	if (!krgnodes_subset(node_set.v, krgnode_online_map))
		return -EPERM;

	/* TODO: Really required? */
	if (krgnode_isset(kerrighed_node_id, node_set.v))
		return -EPERM;

	return do_nodes_remove(&node_set);
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

static int nodes_poweroff(void __user *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	int unused;
	int err;

	if (copy_from_user(&__node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;

	err = krgnodemask_copy_from_user(&node_set.v, &__node_set.v);
	if (err)
		return err;

	rpc_async_m(NODE_POWEROFF, &node_set.v, &unused, sizeof(unused));

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

static int nodes_reboot(void __user *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_node_set node_set;
	int unused;
	
	if (copy_from_user(&__node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;
	
	err = krgnodemask_copy_from_user(&node_set.v, &__node_set.v);
	if (err)
		return err;

	rpc_async_m(NODE_REBOOT, &node_set.v,
		    &unused, sizeof(unused));
	
	return 0;
}
*/

int hotplug_remove_init(void)
{
	rpc_register(NODE_POWEROFF, handle_node_poweroff, 0);
	rpc_register_void(NODE_REMOVE, handle_node_remove, 0);
	rpc_register_int(NODE_REMOVE_CONFIRM, handle_node_remove_confirm, 0);

	register_proc_service(KSYS_HOTPLUG_REMOVE, nodes_remove);
	register_proc_service(KSYS_HOTPLUG_POWEROFF, nodes_poweroff);
	/* register_proc_service(KSYS_HOTPLUG_REBOOT, nodes_reboot); */

	return 0;
}

void hotplug_remove_cleanup(void)
{
}
