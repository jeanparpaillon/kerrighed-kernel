/** KDDM IO linker interface.
 *  @file io_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/krgflags.h>

#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kddm/io_linker.h>


struct iolinker_struct *iolinker_list[MAX_IO_LINKER];

krgnodemask_t krgnode_kddm_map;
kerrighed_node_t kddm_nb_nodes;


/*****************************************************************************/
/*                                                                           */
/*                     INSTANTIATE/UNINSTANTIATE FUNCTIONS                   */
/*                                                                           */
/*****************************************************************************/



/** Instantiate a kddm set with an IO linker.
 *  @author Renaud Lottiaux
 *
 *  @param set           Kddm set to instantiate.
 *  @param link          Node linked to the kddm set.
 *  @param iolinker_id   Id of the linker to link to the kddm set.
 *  @param private_data  Data used by the instantiator...
 *
 *  @return  Structure of the requested kddm set or NULL if not found.
 */
int kddm_io_instantiate (struct kddm_set * set,
			 kerrighed_node_t def_owner,
			 iolinker_id_t iolinker_id,
			 void *private_data,
			 int data_size,
			 int master)
{
	int err = 0;

	BUG_ON (set == NULL);
	BUG_ON (iolinker_id < 0 || iolinker_id >= MAX_IO_LINKER);
	BUG_ON (set->state != KDDM_SET_LOCKED);

	while (iolinker_list[iolinker_id] == NULL) {
		WARNING ("Instantiate a kddm set with a not registered IO "
			 "linker (%d)... Retry in 1 second\n", iolinker_id);
		set_current_state (TASK_INTERRUPTIBLE);
		schedule_timeout (1 * HZ);
	}

	set->def_owner = def_owner;
	set->iolinker = iolinker_list[iolinker_id];

	if (data_size) {
		set->private_data = kmalloc (data_size, GFP_KERNEL);
		BUG_ON (set->private_data == NULL);
		memcpy (set->private_data, private_data, data_size);
		set->private_data_size = data_size;
	}
	else {
		set->private_data = NULL;
		set->private_data_size = 0;
	}

	if (set->iolinker->instantiate)
		err = set->iolinker->instantiate (set, private_data,
						  master);

	return err;
}



/** Uninstantiate a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set to uninstantiate
 */
void kddm_io_uninstantiate (struct kddm_set * set,
                            int destroy)
{
	if (set->iolinker && set->iolinker->uninstantiate)
		set->iolinker->uninstantiate (set, destroy);

	if (set->private_data)
		kfree(set->private_data);
	set->private_data = NULL;
	set->iolinker = NULL;
}



/*****************************************************************************/
/*                                                                           */
/*                      MAIN IO LINKER INTERFACE FUNCTIONS                   */
/*                                                                           */
/*****************************************************************************/



/** Request an IO linker to allocate an object.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry    Object entry to export data from.
 *  @param set          Kddm Set the object belong to.
 */
int kddm_io_alloc_object (struct kddm_obj * obj_entry,
			  struct kddm_set * set,
			  objid_t objid)
{
	int r = 0;

	if (obj_entry->object != NULL)
		goto done;

	if (set->iolinker && set->iolinker->alloc_object)
		r = set->iolinker->alloc_object (obj_entry, set, objid);
	else {
		/* Default allocation function */
		obj_entry->object = kmalloc(set->obj_size, GFP_KERNEL);
		if (obj_entry->object == NULL)
			r = -ENOMEM;
	}

	if (obj_entry->object != NULL)
		atomic_inc(&set->nr_objects);

done:
	return r;
}



/** Request an IO linker to do an object first touch.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to first touch.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_first_touch_object (struct kddm_obj * obj_entry,
                                struct kddm_set * set,
                                objid_t objid,
				int flags)
{
	int res = 0 ;

	BUG_ON (obj_entry->object != NULL);
	BUG_ON (OBJ_STATE(obj_entry) != INV_FILLING);

	if (set->iolinker && set->iolinker->first_touch) {
		res = set->iolinker->first_touch (obj_entry, set,
						  objid, flags);
		if (obj_entry->object)
			atomic_inc(&set->nr_objects);
	}
	else
		res = kddm_io_alloc_object(obj_entry, set, objid);

	return res ;
}



/** Request an IO linker to insert an object in a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to insert.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_insert_object (struct kddm_obj * obj_entry,
                           struct kddm_set * set,
                           objid_t objid)
{
	int res = 0;

	if (set->iolinker && set->iolinker->insert_object)
		res = set->iolinker->insert_object (obj_entry, set,
						    objid);

	return res;
}



/** Request an IO linker to put a kddm object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to put.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_put_object (struct kddm_obj * obj_entry,
                        struct kddm_set * set,
                        objid_t objid)
{
	int res = 0;

	if (set && set->iolinker->put_object)
		res = set->iolinker->put_object (obj_entry, set,
						 objid);

	return res;
}



/** Request an IO linker to invalidate an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to invalidate.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_invalidate_object (struct kddm_obj * obj_entry,
			       struct kddm_set * set,
			       objid_t objid)
{
	int res = 0;

	if (obj_entry->object) {
		if (set->iolinker && set->iolinker->invalidate_object) {
			res = set->iolinker->invalidate_object (obj_entry,
								set, objid);

			if (res != KDDM_IO_KEEP_OBJECT)
				obj_entry->object = NULL;
		}

		if (obj_entry->object == NULL)
			atomic_dec(&set->nr_objects);
	}

	return res;
}



/** Request an IO linker to remove an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to remove.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_remove_object (void *object,
			   struct kddm_set * set,
			   objid_t objid)
{
	int res = 0;

	if (set->iolinker && set->iolinker->remove_object) {
		might_sleep();
		res = set->iolinker->remove_object (object, set, objid);
	}
	else
		/* Default free function */
		kfree (object);

	atomic_dec(&set->nr_objects);

	return res;
}

int kddm_io_remove_object_and_unlock (struct kddm_obj * obj_entry,
				      struct kddm_set * set,
				      objid_t objid,
				      struct kddm_obj_list **dead_list)
{
	int res = 0;
	void *object;
	struct kddm_obj_list *dead_entry;

	object = obj_entry->object;

	if (object == NULL) {
		put_kddm_obj_entry(set, obj_entry, objid);
		goto done;
	}

	obj_entry->object = NULL;
	put_kddm_obj_entry(set, obj_entry, objid);

	if (dead_list) {
		res = -ENOMEM;
		dead_entry = kmalloc(sizeof(*dead_entry), GFP_ATOMIC);
		if (dead_entry) {
			dead_entry->next = *dead_list;
			dead_entry->object = object;
			dead_entry->objid = objid;
			*dead_list = dead_entry;
			res = 0;
		} else {
			OOM;
		}
	} else {
		res = kddm_io_remove_object (object, set, objid);
	}

done:
	return res;
}



/** Request an IO linker to sync an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param obj_entry    Object entry the object belong to.
 */
int kddm_io_sync_object (struct kddm_obj * obj_entry,
                         struct kddm_set * set,
                         objid_t objid)
{
	int res = 0 ;

	if (set->iolinker && set->iolinker->sync_object)
		res = set->iolinker->sync_object (obj_entry, set, objid);
	else
		BUG();

	return res ;
}



/** Inform an IO linker that an object state has changed.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry    Object entry the object belong to.
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param new_state    New state for the object.
 */
int kddm_io_change_state (struct kddm_obj * obj_entry,
			  struct kddm_set * set,
			  objid_t objid,
			  kddm_obj_state_t new_state)
{
	if (set->iolinker && set->iolinker->change_state)
		set->iolinker->change_state (obj_entry, set, objid, new_state);

	return 0 ;
}



/** Request an IO linker to import data into an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to import data into.
 *  @param buffer       Buffer containing data to import.
 */
int kddm_io_import_object (struct rpc_desc *desc,
                           struct kddm_set *set,
                           struct kddm_obj *obj_entry,
                           objid_t objid,
			   int flags)
{
	struct iolinker_struct *io = set->iolinker;
	int res;

	BUG_ON (OBJ_STATE(obj_entry) != INV_FILLING);

	might_sleep();

	if (io && io->import_object)
		res = io->import_object(desc, set, obj_entry, objid, flags);
	else
		res = rpc_unpack(desc, 0, obj_entry->object, set->obj_size);

	return res;
}



/** Request an IO linker to export data from an object.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to export data from.
 *  @param desc		RPC descriptor to export data on.
 */
int kddm_io_export_object (struct rpc_desc *desc,
			   struct kddm_set *set,
                           struct kddm_obj *obj_entry,
                           objid_t objid,
			   int flags)
{
	struct iolinker_struct *io = set->iolinker;
	int res;

	if (io && io->export_object)
		res = io->export_object(desc, set, obj_entry, objid, flags);
	else
		res = rpc_pack(desc, 0, obj_entry->object, set->obj_size);

	return res;
}

kerrighed_node_t __kddm_io_default_owner (struct kddm_set *set,
					  objid_t objid,
					  const krgnodemask_t *nodes,
					  int nr_nodes)
{
	kerrighed_node_t node;

	if (unlikely(__krgnodes_empty(nodes)))
		return kerrighed_node_id;

	switch (set->def_owner) {
	  case KDDM_RR_DEF_OWNER:
		  node = __nth_krgnode(objid % nr_nodes, nodes);
		  break;

	  case KDDM_UNIQUE_ID_DEF_OWNER:
		  node = objid >> UNIQUE_ID_NODE_SHIFT;
		  if (unlikely(!__krgnode_isset(node, nodes)))
			  node = __nth_krgnode(objid % nr_nodes, nodes);
		  break;

	  case KDDM_CUSTOM_DEF_OWNER:
		  node = set->iolinker->default_owner (set, objid,
						       nodes, nr_nodes);
		  break;

	  default:
		  node = set->def_owner;
		  /* WARNING: Fallback must match with __kddm_set_mgr() */
		  if (unlikely(!__krgnode_isset(node, nodes)))
			  node = __nth_krgnode(node % nr_nodes, nodes);
	}

	return node;
}

kerrighed_node_t kddm_io_default_owner (struct kddm_set * set, objid_t objid)
{
	return __kddm_io_default_owner (set, objid,
					&krgnode_kddm_map,
					kddm_nb_nodes);
}


/*****************************************************************************/
/*                                                                           */
/*                           IO LINKER INIT FUNCTIONS                        */
/*                                                                           */
/*****************************************************************************/



/** Register a new kddm set IO linker.
 *  @author Renaud Lottiaux
 *
 *  @param io_linker_id
 *  @param linker
 */
int register_io_linker (int linker_id,
                        struct iolinker_struct *io_linker)
{
	if(iolinker_list[linker_id] != NULL)
		return -1;

	iolinker_list[linker_id] = io_linker;

	return 0;
}



/** Initialise the IO linker array with existing linker
 */
void io_linker_init (void)
{
	int i;

	kddm_nb_nodes = 1;
	krgnodes_clear(krgnode_kddm_map);
	krgnode_set(kerrighed_node_id, krgnode_kddm_map);

	for (i = 0; i < MAX_IO_LINKER; i++)
		iolinker_list[i] = NULL;
}



/** Initialise the IO linker array with existing linker
 */
void io_linker_finalize (void)
{
}
