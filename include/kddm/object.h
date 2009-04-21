/** Definition and management of kddm objects.
 *  @file object.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_OBJECT__
#define __KDDM_OBJECT__

#include <linux/highmem.h>

#include <kddm/kddm_types.h>
#include <kddm/kddm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   MACROS                                 *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/************************** Copyset management **************************/

/** Get the copyset */
#define COPYSET(obj_entry) (&(obj_entry)->master_obj.copyset)
#define RMSET(obj_entry) (&(obj_entry)->master_obj.rmset)

/** Clear the copyset */
#define CLEAR_SET(set) __krgnodes_clear(set)

/** Duplicate the copyset */
#define DUP2_SET(set, v) __krgnodes_copy(v, set)

/** Tests the presence of a node in the copyset */
#define NODE_IN_SET(set,nodeid) __krgnode_isset(nodeid, set)

/** Tests if local node is the object owner */

#define I_AM_OWNER(obj_entry) ((obj_entry)->flags & KDDM_OWNER_OBJ)

/** Tests if the copyset is empty */
#define SET_IS_EMPTY(set) __krgnodes_empty(set)

/** Tests if the local node own the exclusive copy of the object */
#define OBJ_EXCLUSIVE(obj_entry) (krgnode_is_unique(kerrighed_node_id, (obj_entry)->master_obj.copyset) || \
				  krgnode_is_unique(get_prob_owner(obj_entry), (obj_entry)->master_obj.copyset))

#define OBJ_EXCLUSIVE2(set) (__krgnode_is_unique(kerrighed_node_id, set))

/** Add a node in the copyset */
#define ADD_TO_SET(set,nodeid) __krgnode_set(nodeid, set)

/** Remove a node from the copyset */
#define REMOVE_FROM_SET(set,nodeid) __krgnode_clear(nodeid, set)

#define I_AM_DEFAULT_OWNER(set, objid) \
        (kerrighed_node_id == kddm_io_default_owner(set, objid))

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern atomic_t nr_master_objects;  /*< Number of local master objects */
extern atomic_t nr_copy_objects;    /*< Number of local copy objects */
extern atomic_t nr_OBJ_STATE[]; /*< Number of objects in each possible state */
extern const char *state_name[]; /*< Printable state name */



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define ASSERT_OBJ_LOCKED(set, objid) assert_spin_locked(&(set)->obj_lock[(objid) % NR_OBJ_ENTRY_LOCKS])

#define OBJ_IS_LOCKED(set, objid) spin_is_locked(&(set)->obj_lock[(objid) % NR_OBJ_ENTRY_LOCKS])

/** Lock the object (take care about the interrupt context) **/
static inline void kddm_obj_lock (struct kddm_set *set,
				  objid_t objid)
{
	spinlock_t *lock = &set->obj_lock[objid % NR_OBJ_ENTRY_LOCKS];

	if (irqs_disabled ())
		spin_lock (lock);
	else
		spin_lock_bh (lock);
}

static inline void kddm_obj_unlock (struct kddm_set *set,
				    objid_t objid)
{
	spinlock_t *lock = &set->obj_lock[objid % NR_OBJ_ENTRY_LOCKS];

	if (irqs_disabled ())
		spin_unlock (lock);
	else
		spin_unlock_bh (lock);
}



/** Alloc a new KDDM obj entry structure.
 *  @author Renaud Lottiaux
 *
 *  @param set     Kddm set to create an object for.
 *  @param objid   Id of the object to create.
 */
struct kddm_obj *alloc_kddm_obj_entry(struct kddm_set *set,
				      objid_t objid);



/** Free KDDM obj entry structure.
 *  @author Renaud Lottiaux
 *
 *  @param set        The set the object belongs to.
 *  @param obj_entry  The structure to free
 *  @param objid      Id of the object to free.
 */
void free_kddm_obj_entry(struct kddm_set *set,
			 struct kddm_obj *obj_entry,
			 objid_t objid);

/** Lookup for an object entry in a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param kddm_set    Kddm set to lookup the object in.
 *  @param objid       Id of the object to lookup for.
 *
 *  @return        Object entry of the object or NULL if the object entry does
 *                 not exist.
 */
struct kddm_obj *__get_kddm_obj_entry (struct kddm_set *kddm_set,
				       objid_t objid);

static inline struct kddm_obj *_get_kddm_obj_entry (struct kddm_ns *ns,
						    kddm_set_id_t set_id,
						    objid_t objid,
						    struct kddm_set **kddm_set)
{
	struct kddm_obj *obj = NULL;

	*kddm_set = _find_get_kddm_set (ns, set_id);
	if (*kddm_set) {
		obj = __get_kddm_obj_entry (*kddm_set, objid);
		put_kddm_set(*kddm_set);
	}
	return obj;
}

static inline struct kddm_obj *get_kddm_obj_entry (int ns_id,
						   kddm_set_id_t set_id,
						   objid_t objid,
						   struct kddm_set **kddm_set)
{
	struct kddm_obj *obj = NULL;

	*kddm_set = find_get_kddm_set (ns_id, set_id);
	if (*kddm_set) {
		obj = __get_kddm_obj_entry (*kddm_set, objid);
		put_kddm_set(*kddm_set);
	}
	return obj;
}



struct kddm_obj *default_get_kddm_obj_entry (struct kddm_set *set,
					     objid_t objid);



/** Lookup for an object entry in a kddm set and create it if necessary
 *  @author Renaud Lottiaux
 *
 *  @param kddm_set    Kddm set to lookup the object in.
 *  @param objid       Id of the object to lookup for.
 *
 *  @return        Object entry of the object. If the object does not exist,
 *                 it is allocated
 */
struct kddm_obj *__get_alloc_kddm_obj_entry (struct kddm_set *kddm_set,
					     objid_t objid);

static inline struct kddm_obj *get_alloc_kddm_obj_entry (int ns_id,
							 kddm_set_id_t set_id,
							 objid_t objid,
							 struct kddm_set **kddm_set)
{
	struct kddm_obj *obj = NULL;

	*kddm_set = find_get_kddm_set (ns_id, set_id);
	if (*kddm_set) {
		obj = __get_alloc_kddm_obj_entry (*kddm_set, objid);
		put_kddm_set(*kddm_set);
	}
	return obj;
}

static inline struct kddm_obj *_get_alloc_kddm_obj_entry (struct kddm_ns *ns,
							  kddm_set_id_t set_id,
							  objid_t objid,
							  struct kddm_set **kddm_set)
{
	struct kddm_obj *obj = NULL;

	*kddm_set = _find_get_kddm_set (ns, set_id);
	if (*kddm_set) {
		obj = __get_alloc_kddm_obj_entry (*kddm_set, objid);
		put_kddm_set(*kddm_set);
	}
	return obj;
}



int destroy_kddm_obj_entry (struct kddm_set *kddm_set,
			    struct kddm_obj *obj_entry,
			    objid_t objid,
			    int cluster_wide_remove);

void __for_each_kddm_object(struct kddm_set *kddm_set,
			    int(*f)(unsigned long, void *, void*),
			    void *data);

void for_each_kddm_object(int ns_id, kddm_set_id_t set_id,
			  int(*f)(unsigned long, void*, void*),
			  void *data);

/** Insert a new object frame in a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param set          Kddm set to insert object in.
 *  @param objid        Id of the object to insert.
 *  @param state        State of the object to insert.
 */
void kddm_insert_object (struct kddm_set *set, objid_t objid,
                         struct kddm_obj * obj_entry,
			 kddm_obj_state_t state);


/** Change a kddm object state.
 *  @author Renaud Lottiaux
 *
 *  @param kddm_set   Kddm set hosting the object.
 *  @param obj_entry  Structure of the object.
 *  @param objid      Id of the object to modify state.
 *  @param new_state  New state of the object.
 */
void kddm_change_obj_state(struct kddm_set * kddm_set,
			   struct kddm_obj *obj_entry,
			   objid_t objid,
			   kddm_obj_state_t newState);


/** Invalidate a object frame from a kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry  Entry of the object to invalidate.
 *  @param set        Kddm set hosting the object.
 *  @param objid      Id of the object to invalidate.
 */
void kddm_invalidate_local_object_and_unlock (struct kddm_obj *obj_entry,
					      struct kddm_set *set,
					      objid_t objid,
					      kddm_obj_state_t state);



/** Indicate if an object is frozen, ie if it should not be modified.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry  Entry of the object to test.
 */
int object_frozen (struct kddm_obj * obj_entry, struct kddm_set *set);

int object_frozen_or_pinned (struct kddm_obj * obj_entry,
			     struct kddm_set * set);



/** Freeze the given object.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry  Entry of the object to freeze.
 */
void set_object_frozen (struct kddm_obj * obj_entry, struct kddm_set *set);



/** Object clear Frozen.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry  Entry of the object to warm.
 */
void object_clear_frozen (struct kddm_obj * obj_entry, struct kddm_set *set);



static inline int change_prob_owner(struct kddm_obj * obj_entry,
				     kerrighed_node_t new_owner)
{
	if (obj_entry)
		obj_entry->flags = (obj_entry->flags & ~PROB_OWNER_MASK) |
			(new_owner << PROB_OWNER_SHIFT);
	return 0;
}



static inline kerrighed_node_t get_prob_owner (struct kddm_obj *obj_entry)
{
	if (likely(obj_entry))
		return (obj_entry->flags & PROB_OWNER_MASK) >>PROB_OWNER_SHIFT;
	else
		return KERRIGHED_NODE_ID_NONE;
}



/** Unlock, and make a process sleep until the corresponding
 *  object is received.
 *  @author Renaud Lottiaux
 *
 *  @param  set        The kddm set the object belong to.
 *  @param  obj_entry  The object to wait for.
 *  @param  objid      Id of the object.
 */
void __sleep_on_kddm_obj (struct kddm_set *set,
			  struct kddm_obj *obj_entry,
			  objid_t objid,
			  int flags);

static inline void sleep_on_kddm_obj (struct kddm_set *set,
				      struct kddm_obj *obj_entry,
				      objid_t objid,
				      int flags)
{
	__sleep_on_kddm_obj (set, obj_entry, objid, flags);
}

int check_sleep_on_local_exclusive (struct kddm_set *set,
				    struct kddm_obj *obj_entry,
				    objid_t objid,
				    int flags);


/** Wake up the process waiting for the object.
 *  @author Renaud Lottiaux
 *
 *  @param  obj_entry  The object to wake up waiting process.
 */
static inline void wake_up_on_wait_object (struct kddm_obj *obj_entry,
                                           struct kddm_set *set)
{
	if (atomic_read (&obj_entry->sleeper_count))
		SET_OBJECT_PINNED (obj_entry);
	wake_up (&obj_entry->waiting_tsk);
}

int init_kddm_objects (void);

#endif // __KDDM_OBJECT__
