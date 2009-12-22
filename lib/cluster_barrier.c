/** Cluster wide barrier
 *  @file cluster_barrier.c
 *
 *  Implementation of a cluster wide barrier.
 *
 *  Copyright (C) 2009, Renaud Lottiaux, Kerlabs.
 */

#include <linux/cluster_barrier.h>
#include <linux/hashtable.h>
#include <linux/unique_id.h>
#include <net/krgrpc/rpc.h>

#include <kerrighed/types.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krginit.h>

#define TABLE_SIZE 128

static unique_id_root_t barrier_id_root;
static hashtable_t *barrier_table;

struct barrier_id {
	unique_id_t id;
	int toggle;
};



/*****************************************************************************/
/*                                                                           */
/*                             INTERFACE FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/


struct cluster_barrier *alloc_cluster_barrier(unique_id_t key)
{
	struct cluster_barrier *barrier;
	int r, i;

	if (!key)
		key = get_unique_id(&barrier_id_root);

	if (hashtable_find (barrier_table, key))
		return ERR_PTR(-EEXIST);

	barrier = kmalloc (sizeof(struct cluster_barrier), GFP_KERNEL);
	if (!barrier)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < 2; i++) {
		krgnodes_clear (barrier->core[i].nodes_in_barrier);
		krgnodes_clear (barrier->core[i].nodes_to_wait);
		init_waitqueue_head(&barrier->core[i].waiting_tsk);
		barrier->core[i].in_barrier = 0;
	}
	spin_lock_init(&barrier->lock);
	barrier->id.key = key;
	barrier->id.toggle = 0;

	r = hashtable_add (barrier_table, barrier->id.key, barrier);
	if (r) {
		kfree (barrier);
		return ERR_PTR(r);
	}

	return barrier;
}

void free_cluster_barrier(struct cluster_barrier *barrier)
{
	hashtable_remove (barrier_table, barrier->id.key);

	kfree(barrier);
}

int cluster_barrier(struct cluster_barrier *barrier,
		    krgnodemask_t *nodes,
		    kerrighed_node_t master)
{
	struct cluster_barrier_core *core_bar;
	struct cluster_barrier_id id;
	struct rpc_desc *desc;
	int err = 0;

	BUG_ON (!__krgnode_isset(kerrighed_node_id, nodes));
	BUG_ON (!__krgnode_isset(master, nodes));

	spin_lock(&barrier->lock);
	barrier->id.toggle = (barrier->id.toggle + 1) % 2;
	id = barrier->id;
	core_bar = &barrier->core[id.toggle];
	if (core_bar->in_barrier)
		err = -EBUSY;
	core_bar->in_barrier = 1;
	spin_unlock(&barrier->lock);
	if (err)
		return err;

	desc = rpc_begin(RPC_ENTER_BARRIER, master);

	rpc_pack_type (desc, id);
	rpc_pack(desc, 0, nodes, sizeof(krgnodemask_t));

	rpc_end(desc, 0);

	/* Wait for the barrier to complete */

	wait_event (core_bar->waiting_tsk, (core_bar->in_barrier == 0));

	return 0;
}

/*****************************************************************************/
/*                                                                           */
/*                              REQUEST HANDLERS                             */
/*                                                                           */
/*****************************************************************************/


static int handle_enter_barrier(struct rpc_desc* desc,
				void *_msg, size_t size)
{
	struct cluster_barrier_id *id = ((struct cluster_barrier_id *) _msg);
	struct cluster_barrier_core *core_bar;
	struct cluster_barrier *barrier;
	krgnodemask_t nodes;

	rpc_unpack(desc, 0, &nodes, sizeof(krgnodemask_t));

	barrier = hashtable_find (barrier_table, id->key);
	BUG_ON(!barrier);

	core_bar = &barrier->core[id->toggle];

	if (krgnodes_empty(core_bar->nodes_to_wait)) {
		krgnodes_copy(core_bar->nodes_in_barrier, nodes);
		krgnodes_copy(core_bar->nodes_to_wait, nodes);
	}
	else
		BUG_ON(!krgnodes_equal(core_bar->nodes_in_barrier, nodes));

	krgnode_clear(desc->client, core_bar->nodes_to_wait);

	if (krgnodes_empty(core_bar->nodes_to_wait)) {
                rpc_async_m(RPC_EXIT_BARRIER, &core_bar->nodes_in_barrier,
			    id, sizeof (struct cluster_barrier_id));
	}

	return 0;
}


static int handle_exit_barrier(struct rpc_desc* desc,
			       void *_msg, size_t size)
{
	struct cluster_barrier_id *id = ((struct cluster_barrier_id *) _msg);
	struct cluster_barrier_core *core_bar;
	struct cluster_barrier *barrier;

	barrier = hashtable_find (barrier_table, id->key);
	BUG_ON(!barrier);

	core_bar = &barrier->core[id->toggle];
	core_bar->in_barrier = 0;

	wake_up (&core_bar->waiting_tsk);

	return 0;
}


/*****************************************************************************/
/*                                                                           */
/*                               INIT / FINALIZE                             */
/*                                                                           */
/*****************************************************************************/

static int barrier_notification(struct notifier_block *nb,
				hotplug_event_t event,
				void *data)
{
	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		rpc_enable(RPC_ENTER_BARRIER);
		rpc_enable(RPC_EXIT_BARRIER);
		break;

	case HOTPLUG_NOTIFY_REMOVE:
		/* TODO */
		break;

	case HOTPLUG_NOTIFY_FAIL:
		/* TODO */
		break;

	default:
		BUG();
	}

	return NOTIFY_OK;
}

void init_cluster_barrier(void)
{
	init_and_set_unique_id_root(&barrier_id_root, CLUSTER_BARRIER_MAX);
	barrier_table = hashtable_new(TABLE_SIZE);

	rpc_register_int (RPC_ENTER_BARRIER, handle_enter_barrier, 0);
	rpc_register_int (RPC_EXIT_BARRIER, handle_exit_barrier, 0);

	register_hotplug_notifier(barrier_notification, HOTPLUG_PRIO_BARRIER);
}
