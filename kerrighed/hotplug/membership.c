#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/cluster_barrier.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>

static DECLARE_RWSEM(online_sem);
static struct cluster_barrier *online_barrier;

void membership_online_hold(void)
{
	down_read_non_owner(&online_sem);
}

int membership_online_try_hold(void)
{
	return down_read_trylock_non_owner(&online_sem);
}

void membership_online_release(void)
{
	up_read_non_owner(&online_sem);
}

static void membership_online_add(krgnodemask_t *vector)
{
	BUG_ON(krgnodes_intersects(*vector, krgnode_online_map));

	krgnodes_or(krgnode_online_map, krgnode_online_map, *vector);
	kerrighed_nb_nodes += krgnodes_weight(*vector);
}

static int membership_online_remove(krgnodemask_t *vector)
{
	krgnodemask_t nodes;
	kerrighed_node_t master;
	int err;

	BUG_ON(!krgnodes_subset(*vector, krgnode_online_map));

	down_write(&online_sem);

	krgnodes_copy(nodes, krgnode_online_map);
	master = first_krgnode(nodes);

	err = cluster_barrier(online_barrier, &nodes, master);
	if (err)
		goto unlock;

	krgnodes_andnot(krgnode_online_map, krgnode_online_map, *vector);
	kerrighed_nb_nodes -= krgnodes_weight(*vector);

	err = cluster_barrier(online_barrier, &nodes, master);

unlock:
	up_write(&online_sem);

	return err;
}

static void membership_online_clear(krgnodemask_t *vector)
{
	BUG_ON(!krgnode_isset(kerrighed_node_id, *vector));

	down_write(&online_sem);
	krgnodes_clear(krgnode_online_map);
	kerrighed_nb_nodes = 0;
	up_write(&online_sem);
}

static
int membership_online_notification(struct notifier_block *nb,
				   hotplug_event_t event,
				   void *data)
{
	struct hotplug_context *ctx = data;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		membership_online_add(&ctx->node_set.v);
		break;

	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		membership_online_remove(&ctx->node_set.v);
		break;

	case HOTPLUG_NOTIFY_REMOVE_DISTANT:
		membership_online_clear(&ctx->node_set.v);
		break;

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
	online_barrier = alloc_cluster_barrier(ONLINE_HOTPLUG_BARRIER);
	if (IS_ERR(online_barrier))
		panic("kerrighed: Couldn't alloc online_barrier!\n");

	register_hotplug_notifier(membership_present_notification,
				  HOTPLUG_PRIO_MEMBERSHIP_PRESENT);
	register_hotplug_notifier(membership_online_notification,
				  HOTPLUG_PRIO_MEMBERSHIP_ONLINE);
	return 0;
}

void hotplug_membership_cleanup(void)
{
}
