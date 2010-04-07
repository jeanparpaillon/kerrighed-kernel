/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/nsproxy.h>
#include <linux/hashtable.h>
#include <linux/uaccess.h>
#include <asm/atomic.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/namespace.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>

#include "hotplug_internal.h"

static atomic_t nr_to_wait;
static DECLARE_WAIT_QUEUE_HEAD(all_added_wqh);

int __nodes_add(struct hotplug_context *ctx)
{
	hotplug_add_notify(ctx, HOTPLUG_NOTIFY_ADD);
	return 0;
}

void local_add_done(struct rpc_desc *desc)
{
	rpc_async(NODE_ADD_ACK, desc->comm, rpc_desc_get_client(desc), NULL, 0);
}

static void handle_node_add(struct rpc_desc *rpc_desc, void *data, size_t size)
{
	struct hotplug_context *ctx;
	struct krg_namespace *ns = find_get_krg_ns();
	bool master = rpc_desc_get_client(rpc_desc) == kerrighed_node_id;
	char *page;
	int ret;

	BUG_ON(!ns);
	ctx = hotplug_ctx_alloc(ns);
	put_krg_ns(ns);
	if (!ctx)
		goto out_failed;
	ctx->node_set = *(struct hotplug_node_set *)data;

	if (!master) {
		mutex_lock(&hotplug_mutex);

		ret = rpc_connect_mask(ctx->ns->rpc_comm, &ctx->node_set.v);
		if (ret)
			goto out_failed_unlock;
	}

	ret = __nodes_add(ctx);
	if (ret)
		goto out_failed_close;

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
	if (!master)
		mutex_unlock(&hotplug_mutex);

	local_add_done(rpc_desc);
	return;

out_failed_close:
	if (master)
		goto out_failed_put;
	rpc_close_mask(ctx->ns->rpc_comm, &ctx->node_set.v);
out_failed_unlock:
	mutex_unlock(&hotplug_mutex);
out_failed_put:
	hotplug_ctx_put(ctx);
out_failed:
	printk("kerrighed: [ADD] Failed to add nodes!\n");
}

static void handle_node_add_ack(struct rpc_desc *desc, void *_msg, size_t size)
{
	if (atomic_dec_and_test(&nr_to_wait))
		wake_up(&all_added_wqh);
}

static int check_add_req(struct hotplug_context *ctx)
{
	if (ctx->node_set.subclusterid != kerrighed_subsession_id)
		return -EPERM;
	if (!krgnode_online(kerrighed_node_id))
		return -EPERM;
	if (!krgnodes_subset(ctx->node_set.v, krgnode_present_map))
		return -ENONET;
	if (krgnodes_intersects(ctx->node_set.v, krgnode_online_map))
		return -EPERM;
	return 0;
}

static int do_nodes_add(struct hotplug_context *ctx)
{
	struct rpc_communicator *comm;
	char *page;
	kerrighed_node_t node;
	int ret;

	ret = hotplug_start_request(ctx);
	if (ret)
		goto out;

	mutex_lock(&hotplug_mutex);

	ret = check_add_req(ctx);
	if (ret)
		goto out_finish;

	ret = -ENOMEM;
	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		goto out_finish;

	ret = krgnodelist_scnprintf(page, PAGE_SIZE, ctx->node_set.v);
	BUG_ON(ret >= PAGE_SIZE);
	printk("kerrighed: [ADD] Adding nodes %s ...\n", page);

	free_page((unsigned long)page);

	comm = ctx->ns->rpc_comm;
	ret = rpc_connect_mask(comm, &ctx->node_set.v);
	if (ret)
		goto out_finish;

	atomic_set(&nr_to_wait,
		   num_online_krgnodes() + krgnodes_weight(ctx->node_set.v));

	/*
	 * Send request to all new members
	 * Current limitation: only not-started nodes can be added to a
	 * running cluster (ie: a node can't move from a subcluster to another one)
	 */
	ret = do_cluster_start(ctx);
	if (ret)
		goto err_close;

	/* Send request to all members of the current cluster */
	for_each_online_krgnode(node)
		rpc_async(NODE_ADD, comm, node,
			  &ctx->node_set, sizeof(ctx->node_set));

	wait_event(all_added_wqh, atomic_read(&nr_to_wait) == 0);
	printk("kerrighed: [ADD] Adding nodes succeeded.\n");

out_finish:
	mutex_unlock(&hotplug_mutex);
	hotplug_finish_request(ctx);
out:
	if (ret)
		printk(KERN_ERR "kerrighed: [ADD] Adding nodes failed! err=%d\n",
		       ret);
	return ret;

err_close:
	rpc_close_mask(comm, &ctx->node_set.v);
	goto out_finish;
}

static void nodes_add_work(struct work_struct *work)
{
	struct hotplug_context *ctx;

	ctx = container_of(work, struct hotplug_context, work);

	ctx->ret = do_nodes_add(ctx);
	complete(&ctx->done);

	hotplug_ctx_put(ctx);
}

static int nodes_add(void __user *arg)
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

	err = check_add_req(ctx);
	if (err)
		goto out;

	hotplug_ctx_get(ctx);
	INIT_WORK(&ctx->work, nodes_add_work);
	err = hotplug_queue_request(ctx);
	if (err) {
		hotplug_ctx_put(ctx);
		goto out;
	}

	wait_for_completion(&ctx->done);
	err = ctx->ret;

out:
	hotplug_ctx_put(ctx);

	return err;
}

int hotplug_add_init(void)
{
	rpc_register_void(NODE_ADD, handle_node_add, 0);
	rpc_register_void(NODE_ADD_ACK, handle_node_add_ack, 0);

	register_proc_service(KSYS_HOTPLUG_ADD, nodes_add);
	return 0;
}

void hotplug_add_cleanup(void)
{
}
