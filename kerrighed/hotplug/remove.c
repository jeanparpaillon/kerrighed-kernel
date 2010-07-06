/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/uaccess.h>
#include <linux/nsproxy.h>
#include <kerrighed/namespace.h>
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

static atomic_t nr_to_wait;
static DECLARE_WAIT_QUEUE_HEAD(all_removed_wqh);

static void do_local_node_remove(struct rpc_desc *desc,
				 struct hotplug_context *ctx)
{
	krgnodemask_t new_online;
	int ret;

	SET_KERRIGHED_NODE_FLAGS(KRGFLAGS_STOPPING);
	printk("do_local_node_remove\n");

	krgnodes_andnot(new_online, krgnode_online_map, ctx->node_set.v);
	atomic_set(&nr_to_wait, krgnodes_weight(new_online));

	printk("...notify local\n");
	hotplug_remove_notify(ctx, HOTPLUG_NOTIFY_REMOVE_LOCAL);

	krgnodes_copy(new_online, krgnode_online_map);

	printk("...notify_distant\n");
	hotplug_remove_notify(ctx, HOTPLUG_NOTIFY_REMOVE_DISTANT);

	printk("...confirm\n");
	rpc_sync_m(NODE_REMOVE_CONFIRM, &new_online,
		   &ctx->node_set, sizeof(ctx->node_set));

	printk("...wait ack\n");
	wait_event(all_removed_wqh, atomic_read(&nr_to_wait) == 0);

	rpc_disable_all();

	ret = 0;
	rpc_pack_type(desc, ret);

	CLEAR_KERRIGHED_NODE_FLAGS(KRGFLAGS_RUNNING);
	CLEAR_KERRIGHED_CLUSTER_FLAGS(KRGFLAGS_RUNNING);
	clusters_status[kerrighed_subsession_id] = CLUSTER_UNDEF;

	down_write(&kerrighed_init_sem);
	hooks_stop();
	up_write(&kerrighed_init_sem);

	CLEAR_KERRIGHED_NODE_FLAGS(KRGFLAGS_STOPPING);

	kerrighed_subsession_id = -1;

	rpc_enable(CLUSTER_START);
}

/* we receive the ack from cluster about our remove operation */
static void handle_node_remove_ack(struct rpc_desc *desc, void *data, size_t size)
{
	BUG_ON(desc->client == kerrighed_node_id);
	if (atomic_dec_and_test(&nr_to_wait))
		wake_up(&all_removed_wqh);
}

static void do_other_node_remove(struct rpc_desc *desc,
				 struct hotplug_context *ctx)
{
	int ret;

	printk("do_other_node_remove\n");
	atomic_set(&nr_to_wait, krgnodes_weight(ctx->node_set.v));
	hotplug_remove_notify(ctx, HOTPLUG_NOTIFY_REMOVE_ADVERT);
	rpc_async_m(NODE_REMOVE_ACK, &ctx->node_set.v, NULL, 0);
	wait_event(all_removed_wqh, atomic_read(&nr_to_wait) == 0);

	ret = 0;
	rpc_pack_type(desc, ret);
}

static void handle_node_remove(struct rpc_desc *desc, void *data, size_t size)
{
	struct hotplug_context *ctx;
	struct krg_namespace *ns = find_get_krg_ns();
	char *page;
	int ret;

	BUG_ON(!ns);
	ctx = hotplug_ctx_alloc(ns);
	put_krg_ns(ns);
	if (!ctx) {
		printk("kerrighed: Failed to remove nodes!\n");
		return;
	}
	ctx->node_set = *(struct hotplug_node_set *)data;

	if (krgnode_isset(kerrighed_node_id, ctx->node_set.v)) {
		do_local_node_remove(desc, ctx);
		hotplug_ctx_put(ctx);

		printk("kerrighed: Node removed\n");
		return;
	}

	do_other_node_remove(desc, ctx);
	hotplug_ctx_put(ctx);

	page = (char *)__get_free_page(GFP_KERNEL);
	if (page) {
		ret = krgnodelist_scnprintf(page, PAGE_SIZE, krgnode_online_map);
		BUG_ON(ret >= PAGE_SIZE);
		printk("Kerrighed is running on %d nodes: %s\n",
		       num_online_krgnodes(), page);
		free_page((unsigned long)page);
	} else {
		printk("Kerrighed is running on %d nodes\n", num_online_krgnodes());
	}
}

/* cluster receive the confirmation about the remove operation */
static int handle_node_remove_confirm(struct rpc_desc *desc, void *data, size_t size)
{
	BUG_ON(desc->client == kerrighed_node_id);
	hotplug_remove_notify((void*)&desc->client, HOTPLUG_NOTIFY_REMOVE_ACK);
	if (atomic_dec_and_test(&nr_to_wait))
		wake_up(&all_removed_wqh);
	printk("Kerrighed: node %d removed\n", desc->client);

	return 0;
}

static int check_remove_req(struct hotplug_context *ctx)
{
	if (ctx->node_set.subclusterid != kerrighed_subsession_id)
		return -EPERM;
	if (!krgnode_online(kerrighed_node_id))
		return -EPERM;
	if (!krgnodes_subset(ctx->node_set.v, krgnode_present_map))
		return -ENONET;
	if (!krgnodes_subset(ctx->node_set.v, krgnode_online_map))
		return -EPERM;
	return 0;
}

static int do_nodes_remove(struct hotplug_context *ctx)
{
	char *page;
	int ret;

	ret = check_remove_req(ctx);
	if (ret)
		return ret;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = krgnodelist_scnprintf(page, PAGE_SIZE, ctx->node_set.v);
	BUG_ON(ret >= PAGE_SIZE);
	printk("kerrighed: Removing nodes %s ...\n", page);

	free_page((unsigned long)page);

	ret = rpc_sync_m(NODE_REMOVE, &krgnode_online_map,
			 &ctx->node_set, sizeof(ctx->node_set));
	if (ret)
		printk(KERN_ERR "kerrighed: Removing nodes failed! err=%d\n",
		       ret);
	else
		printk("kerrighed: Removing nodes succeeded.\n");

	return ret;
}

static void self_remove_failed(struct krg_namespace *ns, int err)
{
	printk("kerrighed: "
	       "Failed to automatically remove the node! err = %d"
	       "Please retry manually.\n", err);
}

static void self_remove_work(struct work_struct *work)
{
	struct hotplug_context *ctx;
	int err;

	ctx = container_of(work, struct hotplug_context, work);

	err = do_nodes_remove(ctx);
	if (err)
		self_remove_failed(ctx->ns, err);

	hotplug_ctx_put(ctx);
}

void self_remove(struct krg_namespace *ns)
{
	struct hotplug_context *ctx;

	ctx = hotplug_ctx_alloc(ns);
	if (!ctx) {
		self_remove_failed(ns, -ENOMEM);
		return;
	}
	ctx->node_set.subclusterid = kerrighed_subsession_id;
	ctx->node_set.v = krgnodemask_of_node(kerrighed_node_id);

	INIT_WORK(&ctx->work, self_remove_work);
	queue_work(krg_hotplug_wq, &ctx->work);
}

static int nodes_remove(void __user *arg)
{
	struct __hotplug_node_set __node_set;
	struct hotplug_context *ctx;
	int err;

	if (copy_from_user(&__node_set, arg, sizeof(struct __hotplug_node_set)))
		return -EFAULT;

	ctx = hotplug_ctx_alloc(current->nsproxy->krg_ns);
	if (!ctx)
		return -ENOMEM;

	ctx->node_set.subclusterid = __node_set.subclusterid;
	err = krgnodemask_copy_from_user(&ctx->node_set.v, &__node_set.v);
	if (err)
		goto out;

	err = check_remove_req(ctx);
	if (err)
		goto out;

	err = -EPERM;
	/* TODO: Really required? */
	if (krgnode_isset(kerrighed_node_id, ctx->node_set.v))
		goto out;

	err = do_nodes_remove(ctx);

out:
	hotplug_ctx_put(ctx);

	return err;
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
	rpc_register_void(NODE_REMOVE_ACK, handle_node_remove_ack, 0);
	rpc_register_int(NODE_REMOVE_CONFIRM, handle_node_remove_confirm, 0);

	register_proc_service(KSYS_HOTPLUG_REMOVE, nodes_remove);
	register_proc_service(KSYS_HOTPLUG_POWEROFF, nodes_poweroff);
	/* register_proc_service(KSYS_HOTPLUG_REBOOT, nodes_reboot); */

	return 0;
}

void hotplug_remove_cleanup(void)
{
}
