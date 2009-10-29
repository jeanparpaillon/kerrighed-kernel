/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/workqueue.h>
#include <linux/slab.h>

#include <kerrighed/hotplug.h>
#include <kerrighed/namespace.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "hotplug_internal.h"

struct workqueue_struct *krg_ha_wq;

struct hotplug_context *hotplug_ctx_alloc(struct krg_namespace *ns)
{
	struct hotplug_context *ctx;

	BUG_ON(!ns);
	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	get_krg_ns(ns);
	ctx->ns = ns;
	kref_init(&ctx->kref);

	return ctx;
}

void hotplug_ctx_release(struct kref *kref)
{
	struct hotplug_context *ctx;

	ctx = container_of(kref, struct hotplug_context, kref);
	put_krg_ns(ctx->ns);
	kfree(ctx);
}

int init_hotplug(void)
{
	krg_ha_wq = create_workqueue("krgHA");
	BUG_ON(krg_ha_wq == NULL);

	hotplug_hooks_init();

	hotplug_add_init();
#ifdef CONFIG_KRG_HOTPLUG_DEL
	hotplug_remove_init();
#endif
	hotplug_failure_init();
	hotplug_cluster_init();
	hotplug_namespace_init();
	hotplug_membership_init();

	return 0;
};

void cleanup_hotplug(void)
{
};
