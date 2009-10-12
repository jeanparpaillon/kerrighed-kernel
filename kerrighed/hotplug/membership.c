#include <linux/notifier.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>

static void membership_online_add(krgnodemask_t *vector)
{
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, vector){
		if(krgnode_online(i))
			continue;
		set_krgnode_online(i);
		kerrighed_nb_nodes++;
	}
}

static void membership_online_remove(krgnodemask_t *vector)
{
	kerrighed_node_t i;

	__for_each_krgnode_mask(i, vector){
		if(!krgnode_online(i))
			continue;
		clear_krgnode_online(i);
		kerrighed_nb_nodes--;
	}
}

static
int membership_online_notification(struct notifier_block *nb,
				   hotplug_event_t event,
				   void *data)
{
	
	switch(event){
	case HOTPLUG_NOTIFY_ADD:{
		struct hotplug_context *ctx = data;
		membership_online_add(&ctx->node_set.v);
		break;
	}

	case HOTPLUG_NOTIFY_REMOVE_LOCAL:{
		kerrighed_node_t node;
		for_each_online_krgnode(node)
			if(node != kerrighed_node_id)
				clear_krgnode_online(node);
	}
		
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:{
		struct hotplug_node_set *node_set = data;
		membership_online_remove(&node_set->v);
		break;
	}

	default:
		break;

	} /* switch */
	
	return NOTIFY_OK;
}

static
int membership_present_notification(struct notifier_block *nb,
				    hotplug_event_t event, void *data)
{
	switch(event){
	default:
		break;
	} /* switch */

	return NOTIFY_OK;
}

int hotplug_membership_init(void)
{
	register_hotplug_notifier(membership_present_notification,
				  HOTPLUG_PRIO_MEMBERSHIP_PRESENT);
	register_hotplug_notifier(membership_online_notification,
				  HOTPLUG_PRIO_MEMBERSHIP_ONLINE);
	return 0;
}

void hotplug_membership_cleanup(void)
{
}
