/** Definition and management of kddm objects.
 *  @file object.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_OBJECT__
#define __KDDM_OBJECT__

#include <linux/highmem.h>
#include <linux/hardirq.h>

#include <kddm/kddm_types.h>
#include <kddm/kddm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   MACROS                                 *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** Object states used for the coherence protocol */

typedef enum {
	INV_COPY = 0,
	READ_COPY =         1 << STATE_INDEX_SHIFT | KDDM_READ_OBJ,

	INV_OWNER =         2 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ,
	READ_OWNER =        3 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ | KDDM_READ_OBJ,
	WRITE_OWNER =       4 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ | KDDM_READ_OBJ | KDDM_WRITE_OBJ,
	WRITE_GHOST =       5 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ | KDDM_READ_OBJ | KDDM_WRITE_OBJ,

	WAIT_ACK_INV =      6 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ | KDDM_READ_OBJ,
	WAIT_ACK_WRITE =    7 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ | KDDM_READ_OBJ,
	WAIT_CHG_OWN_ACK =  8 << STATE_INDEX_SHIFT | KDDM_OWNER_OBJ | KDDM_READ_OBJ,

	WAIT_OBJ_READ =    10 << STATE_INDEX_SHIFT,
	WAIT_OBJ_WRITE =   11 << STATE_INDEX_SHIFT,

	WAIT_OBJ_RM_DONE = 13 << STATE_INDEX_SHIFT,
	WAIT_OBJ_RM_ACK =  14 << STATE_INDEX_SHIFT,
	WAIT_OBJ_RM_ACK2 = 15 << STATE_INDEX_SHIFT,

	INV_FILLING =      16 << STATE_INDEX_SHIFT,

	NB_OBJ_STATE =     17 /* MUST always be the last one */
} kddm_obj_state_t;

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

#define KDDM_OBJ_REMOVED 1
#define KDDM_OBJ_CLEARED 2

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/


extern struct kmem_cache *kddm_obj_cachep;
extern atomic_t nr_master_objects;  /*< Number of local master objects */
extern atomic_t nr_copy_objects;    /*< Number of local copy objects */
extern atomic_t nr_OBJ_STATE[]; /*< Number of objects in each possible state */
extern const char *state_name[]; /*< Printable state name */


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

static inline void kddm_lock_obj_table(struct kddm_set * set)
{
	set->ops->lock_obj_table(set);
}

static inline void kddm_unlock_obj_table(struct kddm_set * set)
{
	set->ops->unlock_obj_table(set);
}

static inline void lock_obj_entry(struct kddm_obj *obj_entry)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	spin_lock(&obj_entry->lock);
#else
	while (TEST_AND_SET_OBJECT_LOCKED (obj_entry))
		cpu_relax();
#endif
}

static inline int trylock_obj_entry(struct kddm_obj *obj_entry)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	return spin_trylock(&obj_entry->lock);
#else
	return !TEST_AND_SET_OBJECT_LOCKED (obj_entry);
#endif
}

static inline int is_locked_obj_entry(struct kddm_obj *obj_entry)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	return spin_is_locked(&obj_entry->lock);
#else
	return TEST_OBJECT_LOCKED(obj_entry);
#endif
}

static inline void unlock_obj_entry(struct kddm_obj *obj_entry)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	spin_unlock(&obj_entry->lock);
#else
	CLEAR_OBJECT_LOCKED(obj_entry);
#endif
}

static inline void wait_unlock_obj_entry(struct kddm_obj *obj_entry)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	spin_unlock_wait(&obj_entry->lock);
#else
	while (TEST_OBJECT_LOCKED(obj_entry))
		cpu_relax();
#endif
}

/** Alloc a new KDDM obj entry structure.
 *  @author Renaud Lottiaux
 *
 *  @param set     Kddm set to create an object for.
 *  @param objid   Id of the object to create.
 */
struct kddm_obj *alloc_kddm_obj_entry(struct kddm_set *set,
				      objid_t objid);

/** Duplicate a KDDM obj entry structure.
 *  @author Renaud Lottiaux
 *
 *  @param src_obj   The object entry to duplicate
 */
struct kddm_obj *dup_kddm_obj_entry(struct kddm_obj *src_obj);

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

static inline void free_obj_entry_struct(struct kddm_obj *obj_entry)
{
	kmem_cache_free(kddm_obj_cachep, obj_entry);
}

static inline void inc_obj_entry_refcount(struct kddm_obj *obj_entry)
{
	atomic_inc(&obj_entry->refcount);
}

static inline void dec_obj_entry_refcount(struct kddm_set *set,
					  struct kddm_obj *obj_entry,
					  objid_t objid)
{
	if (atomic_dec_and_test(&obj_entry->refcount))
		free_kddm_obj_entry(set, obj_entry, objid);
}

static inline int obj_entry_refcount(struct kddm_obj *obj_entry)
{
        return atomic_read(&obj_entry->refcount);
}

static inline void inc_obj_entry_mapcount(struct kddm_obj *obj_entry)
{
	if (atomic_inc_return(&obj_entry->mapcount) == 1)
		inc_obj_entry_refcount(obj_entry);
}

static inline void dec_obj_entry_mapcount(struct kddm_set *set,
					  struct kddm_obj *obj_entry,
					  objid_t objid)
{
	if (atomic_dec_and_test(&obj_entry->mapcount))
		dec_obj_entry_refcount(set, obj_entry, objid);
}

static inline int obj_entry_mapcount(struct kddm_obj *obj_entry)
{
        return atomic_read(&obj_entry->mapcount);
}

static inline int do_get_kddm_obj_entry (struct kddm_set *set,
					 struct kddm_obj *obj_entry,
					 objid_t objid)
{
	inc_obj_entry_refcount(obj_entry);
	if (!trylock_obj_entry(obj_entry)) {
		if (set)
			kddm_unlock_obj_table(set);
		wait_unlock_obj_entry(obj_entry);
		dec_obj_entry_refcount(set, obj_entry, objid);
		return -EAGAIN;
	}
	return 0;
}

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

static inline void put_kddm_obj_entry (struct kddm_set *set,
				       struct kddm_obj *obj_entry,
				       objid_t objid)
{
	if (obj_entry) {
		unlock_obj_entry(obj_entry);
		dec_obj_entry_refcount(set, obj_entry, objid);
	}
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
struct kddm_obj *___get_alloc_kddm_obj_entry (struct kddm_set *kddm_set,
					      objid_t objid,
					      int lock_free);

static inline struct kddm_obj *get_alloc_kddm_obj_entry (int ns_id,
							 kddm_set_id_t set_id,
							 objid_t objid,
							 struct kddm_set **kddm_set)
{
	struct kddm_obj *obj = NULL;

	*kddm_set = find_get_kddm_set (ns_id, set_id);
	if (*kddm_set) {
		obj = ___get_alloc_kddm_obj_entry (*kddm_set, objid, 0);
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
		obj = ___get_alloc_kddm_obj_entry (*kddm_set, objid, 0);
		put_kddm_set(*kddm_set);
	}
	return obj;
}

static inline struct kddm_obj *__get_alloc_kddm_obj_entry (
	                                             struct kddm_set *kddm_set,
						     objid_t objid)
{
	return ___get_alloc_kddm_obj_entry(kddm_set, objid, 0);
}

static inline int do_func_on_obj_entry (struct kddm_set *set,
					struct kddm_obj *obj_entry,
					unsigned long objid,
					struct kddm_obj_iterator *iterator)
{
	int r;

	if (!obj_entry)
		return 0;

	if (do_get_kddm_obj_entry(NULL, obj_entry, objid) == -EAGAIN)
		return -EAGAIN;

	r = iterator->f(objid, obj_entry, iterator->data, iterator->dead_list);

	/* Called functions are not allowed to return -EAGAIN */
	BUG_ON (r == -EAGAIN);

	if (r != KDDM_OBJ_REMOVED && r != KDDM_OBJ_CLEARED)
		put_kddm_obj_entry(set, obj_entry, objid);

	return r;
}

int __destroy_kddm_obj_entry(struct kddm_set *kddm_set,
			     struct kddm_obj *obj_entry,
			     objid_t objid,
			     struct kddm_obj_list **dead_list,
			     int cluster_wide_remove);

static inline int destroy_kddm_obj_entry(struct kddm_set *kddm_set,
					 struct kddm_obj *obj_entry,
					 objid_t objid,
					 int cluster_wide_remove)
{
	return __destroy_kddm_obj_entry(kddm_set, obj_entry, objid, NULL,
					cluster_wide_remove);
}

static inline int destroy_kddm_obj_entry_inatomic(struct kddm_set *kddm_set,
						  struct kddm_obj *obj_entry,
						  objid_t objid,
						  struct kddm_obj_list **dead_list)
{
	return __destroy_kddm_obj_entry(kddm_set, obj_entry, objid, dead_list, 0);
}

static inline void ___for_each_kddm_object(struct kddm_set *set,
				   int (*f)(objid_t, struct kddm_obj *, void *, struct kddm_obj_list **),
				   void *data)
{
	struct kddm_obj_iterator iterator;

	iterator.f = f;
	iterator.data = data;
	iterator.dead_list = NULL;
	set->ops->for_each_obj_entry(set, &iterator);
}

void __for_each_kddm_object(struct kddm_set *kddm_set,
			    int (*f)(objid_t, struct kddm_obj *, void *, struct kddm_obj_list **),
			    void *data);

void for_each_kddm_object(int ns_id, kddm_set_id_t set_id,
			  int (*f)(objid_t, struct kddm_obj *, void *, struct kddm_obj_list **),
			  void *data);

void __for_each_kddm_object_safe(struct kddm_set *kddm_set,
				 int (*f)(objid_t, struct kddm_obj *, void *, struct kddm_obj_list **),
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
int object_frozen (struct kddm_obj * obj_entry);

int object_frozen_or_pinned (struct kddm_obj * obj_entry);



/** Freeze the given object.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry  Entry of the object to freeze.
 */
void set_object_frozen (struct kddm_obj * obj_entry);



/** Object clear Frozen.
 *  @author Renaud Lottiaux
 *
 *  @param obj_entry  Entry of the object to warm.
 */
void object_clear_frozen (struct kddm_obj * obj_entry, struct kddm_set *set);

static inline struct kddm_obj *kddm_break_cow_object (struct kddm_set * set,
					      struct kddm_obj *obj_entry,
					      objid_t objid,
					      int break_type)
{
	BUG_ON (object_frozen(obj_entry));

	if (set->ops->break_cow)
		return set->ops->break_cow (set, obj_entry, objid, break_type);
	return obj_entry;
}

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
