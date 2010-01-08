/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/notifier.h>
#include <linux/kernel.h>
#include <kerrighed/krgnodemask.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>

#include "rpc_internal.h"

#ifdef CONFIG_KERRIGHED
static int rpc_add(const krgnodemask_t *vector)
{
	return comlayer_add(vector);
}

static int rpc_remove(const krgnodemask_t *vector)
{
	printk("Have to send all the tx_queue before stopping the node\n");

	comlayer_remove(vector);

	return 0;
}

/**
 *
 * Notifier related part
 *
 */

static int rpc_notification(struct notifier_block *nb, hotplug_event_t event,
			    void *data)
{
	struct hotplug_context *ctx = data;
	struct hotplug_node_set *node_set = data;
	int err;

	switch(event) {
	case HOTPLUG_NOTIFY_ADD:
		err = rpc_add(&ctx->node_set.v);
		break;
	case HOTPLUG_NOTIFY_REMOVE:
		err = rpc_remove(&node_set->v);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}
#endif

int rpc_hotplug_init(void){
#ifdef CONFIG_KERRIGHED
	register_hotplug_notifier(rpc_notification, HOTPLUG_PRIO_RPC);
#endif
	return 0;
};

void rpc_hotplug_cleanup(void){
};
