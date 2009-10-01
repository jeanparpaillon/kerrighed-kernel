/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */
#include <linux/notifier.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/hotplug.h>

#include "proc.h"

struct notifier_block;

inline
void procfs_add(krgnodemask_t * v){
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, v){
		create_proc_node_info(i);
	};

};

inline
void procfs_remove(krgnodemask_t * v){
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, v){
		remove_proc_node_info(i);
	};

};


/**
 *
 * Notifier related part
 *
 */

static int procfs_notification(struct notifier_block *nb, hotplug_event_t event,
			    void *data){
	struct hotplug_node_set *node_set = data;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		procfs_add(&node_set->v);
		break;

	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		procfs_remove(&node_set->v);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
};

int procfs_hotplug_init(void){
	register_hotplug_notifier(procfs_notification, HOTPLUG_PRIO_MEMBERSHIP_ONLINE);
	return 0;
};

void procfs_hotplug_cleanup(void){
};
