/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/hashtable.h>
#include <linux/uaccess.h>
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

int __nodes_add(struct hotplug_context *ctx)
{
	hotplug_add_notify(ctx, HOTPLUG_NOTIFY_ADD);
	return 0;
}

static void handle_node_add(struct rpc_desc *rpc_desc, void *data, size_t size)
{
	struct hotplug_context *ctx;
	struct krg_namespace *ns = find_get_krg_ns();
	char *page;
	int ret;

	BUG_ON(!ns);
	ctx = hotplug_ctx_alloc(ns);
	put_krg_ns(ns);
	if (!ctx) {
		printk("kerrighed: Failed to add nodes!\n");
		return;
	}
	ctx->node_set = *(struct hotplug_node_set *)data;

	__nodes_add(ctx);

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

static int do_nodes_add(struct hotplug_context *ctx)
{
	char *page;
	kerrighed_node_t node;
	int ret;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = krgnodelist_scnprintf(page, PAGE_SIZE, ctx->node_set.v);
	BUG_ON(ret >= PAGE_SIZE);
	printk("kerrighed: Adding nodes %s ...\n", page);

	free_page((unsigned long)page);

	/*
	 * Send request to all new members
	 * Current limitation: only not-started nodes can be added to a
	 * running cluster (ie: a node can't move from a subcluster to another one)
	 */
	ret = do_cluster_start(ctx);
	if (ret) {
		printk(KERN_ERR "kerrighed: Adding nodes failed! err=%d\n",
		       ret);
		return ret;
	}

	/* Send request to all members of the current cluster */
	for_each_online_krgnode(node)
		rpc_async(NODE_ADD, node, &ctx->node_set, sizeof(ctx->node_set));

	printk("kerrighed: Adding nodes succeeded.\n");

	return ret;
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

	err = -EPERM;
	if (ctx->node_set.subclusterid != kerrighed_subsession_id)
		goto out;

	if (!krgnode_online(kerrighed_node_id))
		goto out;

	err = -ENONET;
	if (!krgnodes_subset(ctx->node_set.v, krgnode_present_map))
		goto out;

	krgnodes_andnot(ctx->node_set.v, ctx->node_set.v, krgnode_online_map);

	err = do_nodes_add(ctx);

out:
	hotplug_ctx_put(ctx);

	return err;
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
