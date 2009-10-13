/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <linux/workqueue.h>

#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "hotplug_internal.h"

struct workqueue_struct *krg_ha_wq;

int init_hotplug(void)
{
	krg_ha_wq = create_workqueue("krgHA");
	BUG_ON(krg_ha_wq == NULL);

	hotplug_hooks_init();

	hotplug_add_init();
#ifdef CONFIG_KRG_HOTPLUG_ADD
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
