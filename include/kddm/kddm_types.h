#ifndef __KDDM_SET_TYPES__
#define __KDDM_SET_TYPES__

#include <kddm/kddm_tree.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <kerrighed/types.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              OBJECT TYPES                                *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/*********************     Object states    ***********************/
//
//                                            +------------------------------------------- Object state
//                                            |
//                         |-----------------------------------|
// |31 30 29 28 27 26 25 24|23|22|21|20|19 18 17 16 15 14 13 12|11|10|9|8|7|6|5 4 3 2 1 0|
// |-----------------------|--|--|--|--|-----------------------|--|--|-|-|-|-|-----------|
//             |             |  |  |  |            |             |  | | | | |     |
//             |             |  |  |  |            |             |  | | | | |     |
//             |             |  |  |  |            |             |  | | | | |     +------- Reserved
//             |             |  |  |  |            |             |  | | | | +------------- Remove on SO ACK
//             |             |  |  |  |            |             |  | | | +--------------- Pending event
//             |             |  |  |  |            |             |  | | +----------------- Pinned flag
//             |             |  |  |  |            |             |  | +------------------- SEND_RM_ACK2 flag
//             |             |  |  |  |            |             |  +--------------------- Failure Flag
//             |             |  |  |  |            |             +------------------------ Locked
//             |             |  |  |  |            +-------------------------------------- Object state index
//             |             |  |  |  +--------------------------------------------------- Owner flag
//             |             |  |  +------------------------------------------------------ Read access flag
//             |             |  +--------------------------------------------------------- Write access flag
//             |             +------------------------------------------------------------ Unused
//             +-------------------------------------------------------------------------- Probe Owner

/* Various object flags */
#define REMOVE_ON_SO_ACK     6  /* Remove the object on Send Ownership ACK */
#define OBJECT_PENDING_EVENT 7  /* An event is pending on the object */
#define OBJECT_PINNED        8  /* Lock the object to give waiting
				   processes a change to access
				   the object before a potential
				   invalidation */
#define SEND_RM_ACK2         9  /* The default owner need an ack2 after
				   a global remove is done */
#define FAILURE_FLAG        10
#ifndef CONFIG_DEBUG_SPINLOCK
#define OBJECT_LOCKED       11  /* The object is locked */
#endif

/* Object state */
#define STATE_INDEX_MASK    0x000FF000  /* Mask to extract the state index */
#define STATE_INDEX_SHIFT   12

#define KDDM_OWNER_OBJ      (1 << 20)  /* Object is the master object */
#define KDDM_READ_OBJ       (1 << 21)  /* Object can be read */
#define KDDM_WRITE_OBJ      (1 << 22)  /* Object can be write */

#define OBJECT_STATE_MASK   0x00FFF000

/* Probe owner */
#define PROB_OWNER_MASK     0xFF000000
#define PROB_OWNER_SHIFT    24

/* Helper macros */

#define SET_OBJECT_RM_SO_ACK(obj_entry) \
        set_bit (REMOVE_ON_SO_ACK, &(obj_entry)->flags)
#define CLEAR_OBJECT_RM_SO_ACK(obj_entry) \
        clear_bit (REMOVE_ON_SO_ACK, &(obj_entry)->flags)
#define TEST_OBJECT_RM_SO_ACK(obj_entry) \
        test_bit (REMOVE_ON_SO_ACK, &(obj_entry)->flags)

#define SET_OBJECT_PINNED(obj_entry) \
        set_bit (OBJECT_PINNED, &(obj_entry)->flags)
#define CLEAR_OBJECT_PINNED(obj_entry) \
        clear_bit (OBJECT_PINNED, &(obj_entry)->flags)
#define TEST_OBJECT_PINNED(obj_entry) \
        test_bit (OBJECT_PINNED, &(obj_entry)->flags)

#ifndef CONFIG_DEBUG_SPINLOCK
#define SET_OBJECT_LOCKED(obj_entry) \
	BUG_ON(test_bit(OBJECT_LOCKED, &(obj_entry)->flags));\
        set_bit(OBJECT_LOCKED, &(obj_entry)->flags)
#define TEST_AND_SET_OBJECT_LOCKED(obj_entry) \
        test_and_set_bit(OBJECT_LOCKED, &(obj_entry)->flags)
#define CLEAR_OBJECT_LOCKED(obj_entry) \
        clear_bit(OBJECT_LOCKED, &(obj_entry)->flags)
#define TEST_OBJECT_LOCKED(obj_entry) \
        test_bit(OBJECT_LOCKED, &(obj_entry)->flags)
#endif

#define SET_OBJECT_PENDING(obj_entry) \
        set_bit(OBJECT_PENDING_EVENT, &(obj_entry)->flags)
#define CLEAR_OBJECT_PENDING(obj_entry) \
        clear_bit(OBJECT_PENDING_EVENT, &(obj_entry)->flags)
#define TEST_OBJECT_PENDING(obj_entry) \
        test_bit(OBJECT_PENDING_EVENT, &(obj_entry)->flags)

#define SET_OBJECT_RM_ACK2(obj_entry) \
        set_bit (SEND_RM_ACK2, &(obj_entry)->flags)
#define CLEAR_OBJECT_RM_ACK2(obj_entry) \
        clear_bit (SEND_RM_ACK2, &(obj_entry)->flags)
#define TEST_OBJECT_RM_ACK2(obj_entry) \
        test_bit (SEND_RM_ACK2, &(obj_entry)->flags)

#define SET_FAILURE_FLAG(obj_entry) \
        set_bit (FAILURE_FLAG, &(obj_entry)->flags)
#define CLEAR_FAILURE_FLAG(obj_entry) \
        clear_bit (FAILURE_FLAG, &(obj_entry)->flags)
#define TEST_FAILURE_FLAG(obj_entry) \
        test_bit (FAILURE_FLAG, &(obj_entry)->flags)

#define OBJ_STATE(object) \
        (int)((object)->flags & OBJECT_STATE_MASK)
#define OBJ_STATE_INDEX(state) \
        (((state) & STATE_INDEX_MASK) >> STATE_INDEX_SHIFT)
#define STATE_NAME(state) \
        state_name[OBJ_STATE_INDEX(state)]
#define INC_STATE_COUNTER(state) \
        atomic_inc (&nr_OBJ_STATE[OBJ_STATE_INDEX(state)])
#define DEC_STATE_COUNTER(state) \
        atomic_inc (&nr_OBJ_STATE[OBJ_STATE_INDEX(state)])


/** kddm object identifier */
typedef unsigned long objid_t;


/** Master object type.
 *  Type used to store the copy set.
 */
typedef struct {
	krgnodemask_t copyset;   /**< Machines owning an object to invalidate */
	krgnodemask_t rmset;     /**< Machines owning an object to remove */
} masterObj_t;



/** Kddm object type.
 *  Used to store local informations on objects.
 */
typedef struct kddm_obj {
	/* flags field must be kept first in the structure */
	long flags;                    /* Flags, state, prob_owner, etc... */
	atomic_t mapcount;         /* Number of structures sharing the object.
				    * Mapping(s) count for 1 in refcount.
				    */
	atomic_t refcount;         /* Reference counter */
	masterObj_t master_obj;        /* Object informations handled by the
					  manager */
	void *object;                  /* Kernel physical object struct */
	atomic_t frozen_count;         /* Number of task freezing the object */
	atomic_t sleeper_count;        /* Nunmber of task waiting on the
					  object */
	wait_queue_head_t waiting_tsk; /* Process waiting for the object */
#ifdef CONFIG_DEBUG_SPINLOCK
	spinlock_t lock;
#endif
} __attribute__((aligned(8))) kddm_obj_t;

struct kddm_obj_list {
	struct kddm_obj_list *next;
	void *object;
	objid_t objid;
};

struct kddm_obj_iterator {
	int (*f)(objid_t, struct kddm_obj *, void *, struct kddm_obj_list **);
	void *data;
	struct kddm_obj_list **dead_list;
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                               KDDM SET TYPES                             *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** KDDM set flags */
#define _KDDM_LOCAL_EXCLUSIVE  0
#define _KDDM_FT_LINKED        1
#define _KDDM_FROZEN           2
#define _KDDM_NEED_SAFE_WALK   3

#define KDDM_LOCAL_EXCLUSIVE  (1<<_KDDM_LOCAL_EXCLUSIVE)
#define KDDM_FT_LINKED        (1<<_KDDM_FT_LINKED)
#define KDDM_FROZEN           (1<<_KDDM_FROZEN)
#define KDDM_NEED_SAFE_WALK   (1<<_KDDM_NEED_SAFE_WALK)

#define kddm_local_exclusive(kddm) test_bit(_KDDM_LOCAL_EXCLUSIVE, &kddm->flags)
#define set_kddm_local_exclusive(kddm) set_bit(_KDDM_LOCAL_EXCLUSIVE, &kddm->flags);
#define clear_kddm_local_exclusive(kddm) clear_bit(_KDDM_LOCAL_EXCLUSIVE, &kddm->flags);

#define kddm_ft_linked(kddm) test_bit(_KDDM_FT_LINKED, &kddm->flags)
#define set_kddm_ft_linked(kddm) set_bit(_KDDM_FT_LINKED, &kddm->flags);
#define clear_kddm_ft_linked(kddm) clear_bit(_KDDM_FT_LINKED, &kddm->flags);

#define kddm_frozen(kddm) test_bit(_KDDM_FROZEN, &(kddm)->flags)
#define set_kddm_frozen(kddm) set_bit(_KDDM_FROZEN, &(kddm)->flags);
#define clear_kddm_frozen(kddm) clear_bit(_KDDM_FROZEN, &(kddm)->flags);

#define kddm_need_safe_walk(kddm) test_bit(_KDDM_NEED_SAFE_WALK, &(kddm)->flags)
#define set_kddm_need_safe_walk(kddm) set_bit(_KDDM_NEED_SAFE_WALK, &(kddm)->flags);
#define clear_kddm_need_safe_walk(kddm) clear_bit(_KDDM_NEED_SAFE_WALK, &(kddm)->flags);

#define KDDM_BREAK_COW_COPY 1
#define KDDM_BREAK_COW_INV 2

#define NR_OBJ_ENTRY_LOCKS 16


struct kddm_set;
struct rpc_desc;

typedef struct kddm_set_ops {
	void *(*obj_set_alloc) (struct kddm_set *set, void *data);
	void (*obj_set_free) (struct kddm_set *set,
			      struct kddm_obj_iterator *iterator);
	struct kddm_obj *(*lookup_obj_entry)(struct kddm_set *set,
					     objid_t objid);
	struct kddm_obj *(*get_obj_entry)(struct kddm_set *set,
					  objid_t objid, struct kddm_obj *obj);
	void (*insert_object)(struct kddm_set * set, objid_t objid,
			      struct kddm_obj *obj_entry);
	struct kddm_obj *(*break_cow)(struct kddm_set * set,
				      struct kddm_obj *obj_entry,objid_t objid,
				      int break_type);
	void (*remove_obj_entry) (struct kddm_set *set, objid_t objid);
	void (*for_each_obj_entry)(struct kddm_set *set,
				   struct kddm_obj_iterator *iterator);
	void (*export) (struct rpc_desc* desc, struct kddm_set *set);
	void *(*import) (struct rpc_desc* desc, int *free_data);
	void (*lock_obj_table)(struct kddm_set *set);
	void (*unlock_obj_table)(struct kddm_set *set);
} kddm_set_ops_t;



typedef unique_id_t kddm_set_id_t;   /**< Kddm set identifier */

typedef int iolinker_id_t;           /**< IO Linker identifier */

/** KDDM set structure */

typedef struct kddm_set {
	void *obj_set;               /**< Structure hosting the set objects */
	struct kddm_ns *ns;          /**< kddm set name space */
	struct kddm_set_ops *ops;    /**< kddm set operations */
	kddm_set_id_t id;            /**< kddm set identifier */
	spinlock_t lock;             /**< Structure lock */
	unsigned int obj_size;       /**< size of objects in the set */
	atomic_t nr_objects;         /**< Number of objects locally present */
	unsigned long flags;         /**< Kddm set flags */
	int state;                   /**< State of the set (locked, ...) */
	wait_queue_head_t create_wq; /**< Process waiting for set creation */
	wait_queue_head_t frozen_wq; /**< Process waiting on a frozen KDDM */
	atomic_t count;
	unsigned int last_ra_start;  /**< Start of the last readahead window */
	int ra_window_size;          /**< Size of the readahead window */
	kerrighed_node_t def_owner;  /**< Id of default owner node */
	struct iolinker_struct *iolinker;    /**< IO linker ops */
	struct proc_dir_entry *procfs_entry; /**< entry in /proc/kerrighed/kddm */

	void *private_data;                  /**< Data used to instantiate */
	int private_data_size;               /**< Size of private data... */

	struct list_head event_list;
	spinlock_t event_lock;
	atomic_t nr_masters;
	atomic_t nr_copies;
	atomic_t nr_entries;
	event_counter_t get_object_counter;
	event_counter_t grab_object_counter;
	event_counter_t remove_object_counter;
	event_counter_t flush_object_counter;
	void *private;
} kddm_set_t;



struct kddm_info_struct {
	event_counter_t get_object_counter;
	event_counter_t grab_object_counter;
	event_counter_t remove_object_counter;
	event_counter_t flush_object_counter;

	wait_queue_t object_wait_queue_entry;
	struct kddm_obj *wait_obj;
	int ns_id;
	kddm_set_id_t set_id;
	objid_t obj_id;
};

#endif // __KDDM_SET_TYPES__
