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

static void rpc_remove(krgnodemask_t * vector)
{
	printk("Have to send all the tx_queue before stopping the node\n");
};


/**
 *
 * Notifier related part
 *
 */

#ifdef CONFIG_KERRIGHED
static int rpc_notification(struct notifier_block *nb, hotplug_event_t event,
			    void *data){
	struct hotplug_context *ctx = data;

	switch(event){
	case HOTPLUG_NOTIFY_REMOVE:
		rpc_remove(&ctx->node_set.v);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
};
#endif

int rpc_hotplug_init(void){
#ifdef CONFIG_KERRIGHED
	register_hotplug_notifier(rpc_notification, HOTPLUG_PRIO_RPC);
#endif
	return 0;
};

void rpc_hotplug_cleanup(void){
};
