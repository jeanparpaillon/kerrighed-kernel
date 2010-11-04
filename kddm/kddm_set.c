/** KDDM set interface.
 *  @file kddm_set.c
 *
 *  Implementation of KDDM set manipulation functions.
 *
 *  Copyright (C) 2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <linux/hashtable.h>
#include <linux/unique_id.h>

#include "process.h"
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include <kddm/kddm.h>
#include <kddm/kddm_set.h>
#include <kddm/name_space.h>
#include <kddm/kddm_tree.h>
#include "protocol_action.h"
#include "procfs.h"

struct kmem_cache *kddm_set_cachep;
extern struct kmem_cache *kddm_tree_cachep;
extern struct kmem_cache *kddm_tree_lvl_cachep;

kerrighed_node_t __kddm_set_mgr(struct kddm_set * set,
				const krgnodemask_t *nodes,
				int nr_nodes)
{
	kerrighed_node_t node;

	node = ((kerrighed_node_t)(set->id >> UNIQUE_ID_NODE_SHIFT));
	if (unlikely(!__krgnode_isset(node, nodes)))
		node = __nth_krgnode((node % nr_nodes), nodes);

	return node;
}

/** Alloc a new KDDM set id.
 *  @author Renaud Lottiaux
 *
 *  @param ns     Name space to create the set id in.
 *
 *  @return   A newly allocated KDDM set id.
 */
static inline kddm_set_id_t alloc_new_kddm_set_id (struct kddm_ns *ns)
{
	return get_unique_id (&ns->kddm_set_unique_id_root);
}



/** Alloc a new KDDM set structure.
 *  @author Renaud Lottiaux
 *
 *  @param ns     Name space to create the set in.
 *
 *  @return   A newly allocated KDDM set structure.
 */
static inline struct kddm_set *alloc_kddm_set_struct (struct kddm_ns *ns,
						      kddm_set_id_t set_id,
						      int init_state)
{
	struct kddm_set *kddm_set;

	kddm_set = kmem_cache_alloc (kddm_set_cachep, GFP_ATOMIC);
	if (kddm_set == NULL) {
		kddm_set = ERR_PTR(-ENOMEM);
		goto err;
	}

	/* Make minimal initialisation */

	memset (kddm_set, 0, sizeof(struct kddm_set));
	kddm_set->state = init_state;
	kddm_set->id = set_id;
	kddm_set->ns = ns;
	kddm_set->flags = 0;
	init_waitqueue_head (&kddm_set->create_wq);
	init_waitqueue_head (&kddm_set->frozen_wq);
	spin_lock_init(&kddm_set->lock);
	atomic_set(&kddm_set->count, 1);
	INIT_LIST_HEAD(&kddm_set->event_list);
	spin_lock_init(&kddm_set->event_lock);

err:
	return kddm_set;
}



/** Make full kddm set initialization
 *  @author Renaud Lottiaux
 */
int init_kddm_set (struct kddm_set *set,
		   kddm_set_id_t set_id,
		   struct kddm_set_ops *set_ops,
		   void *tree_init_data,
		   unsigned long flags,
		   kerrighed_node_t def_owner,
		   int obj_size)
{
	int err = -ENOMEM;

	set->ops = set_ops;

	set->id = set_id;
	set->obj_size = obj_size;
	set->flags |= flags;
	set->def_owner = def_owner;
	set->ra_window_size = DEFAULT_READAHEAD_WINDOW_SIZE;
	set->state = KDDM_SET_LOCKED;
	atomic_set (&set->nr_objects, 0);
	atomic_set (&set->nr_masters, 0);
	atomic_set (&set->nr_copies, 0);
	atomic_set (&set->nr_entries, 0);
	set->get_object_counter = 0;
	set->grab_object_counter = 0;
	set->remove_object_counter = 0;
	set->flush_object_counter = 0;
	set->private = NULL;

	set->obj_set = set->ops->obj_set_alloc(set, tree_init_data);
	if (!set->obj_set)
		goto exit;

	/* create /proc/kerrighed/kddm_set entry. */
	set->procfs_entry = create_kddm_proc(set->id);

	err = 0;
exit:
	return err;
}


static int __free_kddm_obj_entry(objid_t index,
				 struct kddm_obj *obj_entry,
				 void *data,
				 struct kddm_obj_list **dead_list)
{
	return KDDM_OBJ_REMOVED;
}

/** Free a kddm set structure. */

void free_kddm_set_struct(struct kddm_set * kddm_set)
{
	struct kddm_obj_iterator iterator;

	{   /// JUST FOR DEBUGGING: BEGIN
		struct kddm_set *_kddm_set;
		_kddm_set = _local_get_kddm_set(kddm_set->ns,
						kddm_set->id);
		BUG_ON (_kddm_set != NULL);
	}   /// JUST FOR DEBUGGING: END

	/*** Free object struct and objects content ***/

	iterator.f = __free_kddm_obj_entry;
	iterator.data = kddm_set;
	iterator.dead_list = NULL;
	kddm_set->ops->obj_set_free(kddm_set, &iterator);

	/*** Get rid of the IO linker ***/

	kddm_io_uninstantiate(kddm_set, 0);

	if (kddm_set->procfs_entry)
		remove_kddm_proc(kddm_set->procfs_entry);

	/*** Finally, we are done... The kddm set is free ***/

	kmem_cache_free(kddm_set_cachep, kddm_set);
}



void put_kddm_set(struct kddm_set *set)
{
	if (atomic_dec_and_test(&set->count))
		free_kddm_set_struct(set);
}
EXPORT_SYMBOL(put_kddm_set);


/** Find a KDDM set structure from its id.
 *  @author Renaud Lottiaux
 *
 *  @param ns            Name space to search the set in.
 *  @param set_id        Identifier of the requested kddm set.
 *  @param init_state    Initial state of the set.
 *  @param flags         Identify extra actions to cary out on the look-up.
 *
 *  @return  Structure of the requested KDDM set.
 *           NULL if the set does not exist.
 */
struct kddm_set *_generic_local_get_kddm_set(struct kddm_ns *ns,
					     kddm_set_id_t set_id,
					     int init_state,
					     int flags)
{
	struct kddm_set *kddm_set;

	if (!(flags & KDDM_LOCK_FREE))
		down_read (&ns->table_sem);
	kddm_set = __hashtable_find (ns->kddm_set_table, set_id);

	if ( (kddm_set != NULL) && (flags & KDDM_CHECK_UNIQUE)) {
		kddm_set = ERR_PTR(-EEXIST);
		goto found;
	}

	if ( (kddm_set == NULL) && (flags & KDDM_ALLOC_STRUCT)) {
		kddm_set = alloc_kddm_set_struct(ns, set_id, init_state);
		if (!(flags & KDDM_LOCK_FREE)) {
			up_read (&ns->table_sem);
			down_write (&ns->table_sem);
		}
		__hashtable_add (ns->kddm_set_table, set_id, kddm_set);
		if (!(flags & KDDM_LOCK_FREE))
			downgrade_write(&ns->table_sem);
	}

	if (likely(kddm_set != NULL))
		atomic_inc(&kddm_set->count);

found:
	if (!(flags & KDDM_LOCK_FREE))
		up_read (&ns->table_sem);

	return kddm_set;
}



/** Find a KDDM set structure from its id.
 *  @author Renaud Lottiaux
 *
 *  @param ns_id         Name space id to search the set in.
 *  @param set_id        Identifier of the requested kddm set.
 *  @param flags         Identify extra actions to cary out on the look-up.
 *
 *  @return  Structure of the requested KDDM set.
 *           NULL if the set does not exist.
 */
struct kddm_set *generic_local_get_kddm_set(int ns_id,
					    kddm_set_id_t set_id,
					    int init_state,
					    int flags)
{
	struct kddm_ns *ns;
	struct kddm_set *kddm_set;

	ns = kddm_ns_get (ns_id);
	if (ns == NULL)
		return ERR_PTR(-EINVAL);
	kddm_set = _generic_local_get_kddm_set(ns , set_id, init_state, flags);
	kddm_ns_put (ns);

	return kddm_set;
}



/** Try to find the given set on a remote node and create a local instance
 *  @author Renaud Lottiaux
 *
 *  @param kddm_set   Struct of the kddm set to lookup.
 *
 *  @return  Structure of the requested kddm set or NULL if not found.
 */
int find_kddm_set_remotely(struct kddm_set *kddm_set)
{
	kerrighed_node_t kddm_set_mgr_node_id ;
	struct kddm_lookup_msg req;
	msg_kddm_set_t *msg;
	int msg_size;
	int err = -ENOMEM;
	struct rpc_desc* desc;
	struct kddm_set_ops *set_ops = NULL;
	void *tree_init_data = NULL;
	int free_init_data = 1;

	kddm_set_mgr_node_id = KDDM_SET_MGR(kddm_set);

	req.lock_free = (kddm_set->ns->state == KDDM_NS_FROZEN);
	req.set_id = kddm_set->id;
	req.ns_id = kddm_set->ns->id;

	desc = rpc_begin(REQ_KDDM_SET_LOOKUP, kddm_set_mgr_node_id);
	rpc_pack_type(desc, req);

	msg_size = sizeof(msg_kddm_set_t) + MAX_PRIVATE_DATA_SIZE;

	msg = kmalloc(msg_size, GFP_KERNEL);
	if (msg == NULL)
		OOM;

	rpc_unpack(desc, 0, msg, msg_size);

	if (msg->kddm_set_id != KDDM_SET_UNUSED) {
		set_ops = krgsyms_import (msg->set_ops);
	tree_init_data = set_ops->import(desc, &free_init_data);
	}

	rpc_end(desc, 0);

	if (msg->kddm_set_id == KDDM_SET_UNUSED) {
		err = -ENOENT;
		goto check_err;
	}

	BUG_ON(msg->kddm_set_id != kddm_set->id);

	err = init_kddm_set(kddm_set, kddm_set->id, set_ops, tree_init_data,
			    msg->flags, msg->link, msg->obj_size);

	if (tree_init_data && free_init_data)
		kfree(tree_init_data);

	if (err != 0)
		goto check_err;

	err = kddm_io_instantiate(kddm_set, msg->link, msg->linker_id,
				  msg->private_data, msg->data_size, 0);

check_err:
	kfree(msg);

	spin_lock(&kddm_set->lock);

	if (err == 0) {
		kddm_set->state = KDDM_SET_READY;
		if (kddm_set->ns->state == KDDM_NS_FROZEN)
			set_kddm_frozen(kddm_set);
	} else
		kddm_set->state = KDDM_SET_INVALID;

	wake_up(&kddm_set->create_wq);

	spin_unlock(&kddm_set->lock);

	return err;
}



/** Return a pointer to the given kddm_set. */

struct kddm_set *__find_get_kddm_set(struct kddm_ns *ns,
				     kddm_set_id_t set_id,
				     int flags)
{
	struct kddm_set *kddm_set;

	flags |= KDDM_ALLOC_STRUCT;
	kddm_set = _generic_local_get_kddm_set(ns, set_id,
					       KDDM_SET_NEED_LOOKUP, flags);
	if (unlikely(IS_ERR(kddm_set)))
		return kddm_set;

	/* If the kddm set has been found INVALID earlier, we have to check if
	 * it is still invalid... So, we force a new remote kddm set lookup.
	 */
	spin_lock(&kddm_set->lock);

	if (kddm_set->state == KDDM_SET_INVALID)
		kddm_set->state = KDDM_SET_NEED_LOOKUP;

	goto check_no_lock;

recheck_state:
	spin_lock(&kddm_set->lock);

check_no_lock:
	/* If KDDM frozen, sleep until it is no more frozen */
	if (!(flags & KDDM_LOCK_FREE) && kddm_frozen(kddm_set)) {
		spin_unlock(&kddm_set->lock);
		wait_event (kddm_set->frozen_wq, (!kddm_frozen(kddm_set)));
		goto recheck_state;
	}

	switch (kddm_set->state) {
	  case KDDM_SET_READY:
		  /* Make sure we only use bypass_frozen when KDDM are frozen (i.e.
		     hotplug cases) */
		  BUG_ON ((flags & KDDM_LOCK_FREE) && !kddm_frozen(kddm_set));
		  spin_unlock(&kddm_set->lock);
		  break;

	  case KDDM_SET_NEED_LOOKUP:
		  /* The kddm set structure has just been allocated or
		   * a remote lookup has been forced.
		   */
		  kddm_set->state = KDDM_SET_LOCKED;
		  spin_unlock(&kddm_set->lock);
		  find_kddm_set_remotely(kddm_set);
		  goto recheck_state;

	  case KDDM_SET_UNINITIALIZED:
	  case KDDM_SET_INVALID:
		  spin_unlock(&kddm_set->lock);
		  kddm_set = NULL;
		  break;

	  case KDDM_SET_LOCKED:
		  sleep_on_and_spin_unlock(&kddm_set->create_wq,
					   &kddm_set->lock);
		  goto recheck_state;

	  default:
		  BUG();
	}

	return kddm_set;
}
EXPORT_SYMBOL(_find_get_kddm_set);


struct kddm_set *find_get_kddm_set(int ns_id,
				   kddm_set_id_t set_id)
{
	struct kddm_ns *ns;
	struct kddm_set *kddm_set;

	ns = kddm_ns_get (ns_id);

	kddm_set = _find_get_kddm_set(ns, set_id);

	kddm_ns_put(ns);

	return kddm_set;
}
EXPORT_SYMBOL(find_get_kddm_set);

struct kddm_set *find_get_kddm_set_lock_free(int ns_id, kddm_set_id_t set_id)
{
	struct kddm_ns *ns;
	struct kddm_set *kddm_set;

	ns = kddm_ns_get(ns_id);
	kddm_set = __find_get_kddm_set(ns, set_id, KDDM_LOCK_FREE);
	kddm_ns_put(ns);

	return kddm_set;
}

/** High level function to create a new kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param ns             Name space to create a new set in.
 *  @param set_id         Id of the kddm set to create. 0 -> auto attribution.
 *  @param order          Order of the number of objects storable in the set.
 *  @param linker_id      Id of the IO linker to link the kddm set with.
 *  @param def_owner      Default owner node.
 *  @param obj_size       Size of objects stored in the kddm set.
 *  @param private_data   Data used by the instantiator.
 *  @param data_size      Size of private data.
 *  @param flags          Kddm set flags.
 *
 *  @return      A newly created kddm set if everything is ok.
 *               Negative value otherwise
 */
struct kddm_set *__create_new_kddm_set(struct kddm_ns *ns,
				       kddm_set_id_t set_id,
				       struct kddm_set_ops *set_ops,
				       void *tree_init_data,
				       iolinker_id_t linker_id,
				       kerrighed_node_t def_owner,
				       int obj_size,
				       void *private_data,
				       unsigned long data_size,
				       unsigned long flags)
{
	struct kddm_set *kddm_set;
	int err = -EINVAL;

	if (data_size > MAX_PRIVATE_DATA_SIZE)
		goto error;

	if (set_id == 0)
		set_id = alloc_new_kddm_set_id(ns);

	kddm_set = _local_get_alloc_unique_kddm_set(ns, set_id,
						    KDDM_SET_UNINITIALIZED);
	if (IS_ERR(kddm_set))
		goto error;

	err = init_kddm_set(kddm_set, set_id, set_ops, tree_init_data,
			    flags, def_owner, obj_size);
	if (err)
		goto error;

	err = kddm_io_instantiate(kddm_set, def_owner, linker_id,
				  private_data, data_size, 1);
	if (err)
		goto error;

	spin_lock(&kddm_set->lock);

	kddm_set->state = KDDM_SET_READY;
	wake_up(&kddm_set->create_wq);

	spin_unlock(&kddm_set->lock);

	put_kddm_set(kddm_set);

	goto exit;

error:
	kddm_set = ERR_PTR(err);
exit:
	return kddm_set;
}
EXPORT_SYMBOL(__create_new_kddm_set);


static void do_freeze_kddm_set(void *_set, void *_data)
{
	struct kddm_set *set = _set;

	spin_lock(&set->lock);

	BUG_ON (kddm_frozen(set));
	set_kddm_frozen(set);
	freeze_kddm_event(set);

	spin_unlock(&set->lock);
}

static void do_unfreeze_kddm_set(void *_set, void *_data)
{
	struct kddm_set *set = _set;

	spin_lock(&set->lock);

	BUG_ON (!kddm_frozen(set));

	unfreeze_kddm_event(set);
	clear_kddm_frozen(set);

	wake_up(&set->frozen_wq);

	spin_unlock(&set->lock);
}

void freeze_kddm(void)
{
	down_read (&kddm_def_ns->table_sem);
	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 do_freeze_kddm_set, NULL);
	kddm_def_ns->state = KDDM_NS_FROZEN;
}

void unfreeze_kddm(void)
{
	kddm_def_ns->state = KDDM_NS_READY;
	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 do_unfreeze_kddm_set, NULL);
	up_read (&kddm_def_ns->table_sem);
}


/*****************************************************************************/
/*                                                                           */
/*                              REQUEST HANDLERS                             */
/*                                                                           */
/*****************************************************************************/

/** kddm set lookup handler.
 *  @author Renaud Lottiaux
 *
 *  @param sender    Identifier of the remote requesting machine.
 *  @param msg       Identifier of the kddm set to lookup for.
 */
int handle_req_kddm_set_lookup(struct rpc_desc* desc,
			       void *_msg, size_t size)
{
	struct kddm_lookup_msg req = *((struct kddm_lookup_msg *) _msg);
	struct kddm_set *kddm_set;
	msg_kddm_set_t *msg;
	int msg_size = sizeof(msg_kddm_set_t);

	kddm_set = generic_local_get_kddm_set(req.ns_id, req.set_id,
					      0, req.lock_free ? KDDM_LOCK_FREE : 0);

	if (kddm_set)
		msg_size += kddm_set->private_data_size;

	/* Prepare the kddm set creation message */

	msg = kmalloc(msg_size, GFP_KERNEL);
	if (msg == NULL)
		OOM;

	if (kddm_set == NULL || kddm_set->state != KDDM_SET_READY) {
		msg->kddm_set_id = KDDM_SET_UNUSED;
		goto done;
	}

	msg->kddm_set_id = req.set_id;
	msg->linker_id = kddm_set->iolinker->linker_id;
	msg->flags = kddm_set->flags;
	msg->link = kddm_set->def_owner;
	msg->obj_size = kddm_set->obj_size;
	msg->data_size = kddm_set->private_data_size;
	msg->set_ops = krgsyms_export (kddm_set->ops);
	memcpy(msg->private_data, kddm_set->private_data, kddm_set->private_data_size);

done:
	rpc_pack(desc, 0, msg, msg_size);
	if (msg->kddm_set_id != KDDM_SET_UNUSED)
		kddm_set->ops->export(desc, kddm_set);

	kfree(msg);

	if (kddm_set)
		put_kddm_set(kddm_set);

	return 0;
}


/** kddm set manager change.
 *  @author Renaud Lottiaux
 *
 *  @param sender    Identifier of the remote requesting machine.
 *  @param msg       Identifier of the kddm set to lookup for.
 */
int handle_req_kddm_set_change_mgr(struct rpc_desc* desc,
				   void *_msg, size_t size)
{
	kddm_id_msg_t *kddm_id = (kddm_id_msg_t *) _msg;
	struct kddm_set *kddm_set;
	bool tweak_map = !krgnode_online(kerrighed_node_id);

	if (tweak_map) {
		/*
		 * This node is being added and should recover the management of
		 * a KDDM set.
		 */
		BUG_ON(kddm_nb_nodes != 1);
		krgnode_kddm_map = krgnodemask_of_node(desc->client);
	}

	kddm_set = find_get_kddm_set_lock_free(kddm_id->ns_id, kddm_id->set_id);
	put_kddm_set(kddm_set);

	if (tweak_map)
		krgnode_kddm_map = krgnodemask_of_node(kerrighed_node_id);

	return 0;
}


/** kddm set destroy handler.
 *  @author Renaud Lottiaux
 *
 *  @param sender    Identifier of the remote requesting machine.
 *  @param msg       Identifier of the kddm set to destroy.
 */
static int do_kddm_set_destroy(kddm_id_msg_t *kddm_id)
{
	struct kddm_ns *ns;
	struct kddm_set *kddm_set;

	BUG_ON(!krgnode_isset(kerrighed_node_id, krgnode_kddm_map));

	/* Remove the kddm set from the name space */

	ns = kddm_ns_get (kddm_id->ns_id);
	if (ns == NULL)
		return -EINVAL;

	down_write (&ns->table_sem);
	kddm_set = __hashtable_remove(ns->kddm_set_table, kddm_id->set_id);
	up_write (&ns->table_sem);

	kddm_ns_put (ns);

	if (kddm_set == NULL)
		return -EINVAL;

	/* Free the kddm set structure */

	put_kddm_set(kddm_set);

	return 0;
}

int handle_req_kddm_set_destroy(struct rpc_desc* desc,
				void *msg, size_t size)
{
	kddm_id_msg_t *kddm_id = (kddm_id_msg_t *) msg;

	return do_kddm_set_destroy(kddm_id);
}

/*****************************************************************************/
/*                                                                           */
/*                INTERFACE FUNCTIONS FOR DISTRIBUTED ACTIONS                */
/*                                                                           */
/*****************************************************************************/


/* High level function to destroy a kddm set. */

int _destroy_kddm_set(struct kddm_set * kddm_set)
{
	kddm_id_msg_t kddm_id;

	kddm_id.set_id = kddm_set->id;
	kddm_id.ns_id = kddm_set->ns->id;

	if (kddm_nb_nodes == 1)
		return do_kddm_set_destroy(&kddm_id);

	rpc_async_m(REQ_KDDM_SET_DESTROY, &krgnode_kddm_map, &kddm_id,
		    sizeof(kddm_id_msg_t));
	return 0;
}
EXPORT_SYMBOL(_destroy_kddm_set);

int destroy_kddm_set(struct kddm_ns *ns, kddm_set_id_t set_id)
{
	struct kddm_set * kddm_set;
	int r;

	kddm_set = _find_get_kddm_set(ns, set_id);
	if (kddm_set == NULL)
		return -EINVAL;
	r = _destroy_kddm_set(kddm_set);

	put_kddm_set(kddm_set);
	return r;
}
EXPORT_SYMBOL(destroy_kddm_set);

/*****************************************************************************/
/*                                                                           */
/*                               INIT / FINALIZE                             */
/*                                                                           */
/*****************************************************************************/



void __kddm_set_destroy(void *_kddm_set,
			void *dummy)
{
	struct kddm_set *kddm_set = _kddm_set;
	kddm_id_msg_t kddm_id;

	kddm_id.ns_id = kddm_set->ns->id;
	kddm_id.set_id = kddm_set->id;

	handle_req_kddm_set_destroy(0, &kddm_id, sizeof(kddm_id));
}



/* KDDM set mecanisms initialisation.*/

void kddm_set_init()
{
	struct rpc_synchro* kddm_server;

	printk ("KDDM set init\n");

	kddm_server = rpc_synchro_new(1, "kddm server", 0);

	kddm_set_cachep = KMEM_CACHE(kddm_set, SLAB_PANIC);

	kddm_tree_cachep = KMEM_CACHE(kddm_tree, SLAB_PANIC);

	kddm_tree_lvl_cachep = KMEM_CACHE(kddm_tree_lvl, SLAB_PANIC);

	__rpc_register(REQ_KDDM_SET_LOOKUP,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       kddm_server, handle_req_kddm_set_lookup, 0);

	__rpc_register(REQ_KDDM_CHANGE_MGR,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_INT,
		       kddm_server, handle_req_kddm_set_change_mgr, 0);

	__rpc_register(REQ_KDDM_SET_DESTROY,
		       RPC_TARGET_NODE, RPC_HANDLER_KTHREAD_VOID,
		       kddm_server, handle_req_kddm_set_destroy, 0);

	printk ("KDDM set init : done\n");
}



void kddm_set_finalize()
{
}
