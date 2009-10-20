#ifndef __KRG_SCHEDULER_PROCESS_SET__
#define __KRG_SCHEDULER_PROCESS_SET__

#include <linux/configfs.h>
#include <linux/pid.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <kerrighed/scheduler/global_config.h>

/**
 * Representation of particual element in process set. This is used both for
 * single processes and process groups.
 */
struct process_set_element {
	struct config_item item;
	pid_t id; /** PID of single process, or PGID of process group,
		    * or SID of process session. */
	struct pid *pid; /** link to locally attached processes */
	struct hlist_node pid_node; /** entry in pid's list of attached
				      * elements  */
	int in_subset;		/** true if still in a subset */
	struct list_head list; /** entry in process_subset */
	struct global_config_item global_item;
};

/**
 * Generic representation of a subset of IDs handled the same way (all PID, or
 * all PGID, etc.)
 */
struct process_subset {
	struct config_group group;
	struct list_head elements_head;
};

/**
 * process_set represents a set of processes that are taken care of by
 * particular scheduler. This set can contain processes or process groups.
 * A particual process_set can be marked that it contains all processes.
 */
struct process_set {
	struct config_group group; /** representation of process set in
				     * configfs. */
	struct global_config_attrs global_attrs;

	int handle_all;		/** if true, process set contains all processes. */
	struct list_head handle_all_list;

	/** subsets of processes that the set contains, separated by PID
	  * classes. */
	struct process_subset subsets[PIDTYPE_MAX];
	/** list of default configfs subdirs */
	struct config_group *def_groups[PIDTYPE_MAX + 1];

	spinlock_t lock; /** lock for synchronizing process set accesses. */

	struct rcu_head rcu;	/** delayed kfree to allow RCU traversals */
};

/** List head of process sets handling all processes */
extern struct list_head process_set_handle_all_head;
/*
 * Lock protecting the list of process sets handling all processes as well as
 * linking between process_set_elements and pids
 */
extern spinlock_t process_set_link_lock;

/**
 * This function allocates memory for new process set and initializes it.
 * Note: at the beginning the process set doesn't contain any processes nor
 * process groups.
 * Note: to free a process set use process_set_put()
 * @author Marko Novak, Louis Rilling
 *
 * @return		pointer to newly created process set or NULL if
 *			creation failed.
 */
struct process_set *process_set_create(void);

/**
 * Mark a process set as deactivated from now, and drop the reference count
 * Assumes that the process set is already removed from configfs
 *
 * @param pset		process set to stop using
 */
void process_set_drop(struct process_set *pset);

/**
 * Get a reference on a process set
 *
 * @param pset		process set to get a reference on
 */
static inline void process_set_get(struct process_set *pset)
{
	if (pset)
		config_group_get(&pset->group);
}

/**
 * Drop a refrence on a process set
 * Dropping last reference frees the process set
 *
 * @param pset		process set which reference to drop
 */
static inline void process_set_put(struct process_set *pset)
{
	if (pset)
		config_group_put(&pset->group);
}

/**
 * Lock a process set
 * This will prevent any addition and removal of elements in the set as well as
 * changing the handle_all flag.
 *
 * @param pset		process set to lock
 */
static inline void process_set_lock(struct process_set *pset)
{
	spin_lock(&pset->lock);
}

/**
 * Unlock a process set
 *
 * @param pset		process set to unlock
 */
static inline void process_set_unlock(struct process_set *pset)
{
	spin_unlock(&pset->lock);
}

/**
 * Tells whether a process set contains all processes
 * Caller must hold process set lock to be sure to obtain a correct result
 * RCU traversals only get a hint without taking process set lock
 *
 * @param pset		process set to test
 *
 * @return		non 0 if pset contains all processes,
 *			0 otherwise
 */
static inline int process_set_contains_all(struct process_set *pset)
{
	return pset->handle_all;
}

/**
 * Prepare a process set for iterations over its elements
 * Must be called before doing any iteration over a process set
 *
 * @param pset		process set to prepare for iteration
 */
static inline void process_set_prepare_do_each_process(struct process_set *pset)
{
	rcu_read_lock();
}

/**
 * do {} while () style macro to begin an iterating loop over the local
 * processes of a process set
 *
 * Note that it's composed of nested loops, so that break will not exit from
 * the loop. Use goto instead.
 * One can use continue to skip the current element however.
 *
 * @param p		task_struct pointer to hold the successive local tasks
 * @param pset		process set to iterate over
 */
#define process_set_do_each_process(p, pset)				   \
	do {								   \
		__label__ __common_begin, __all_end_of_loop;		   \
		struct process_subset *__psubset = NULL;		   \
		struct process_set_element *__pset_el = NULL;		   \
		struct task_struct *__p = NULL;				   \
		struct pid *__pid;					   \
		enum pid_type __type;					   \
		int __all = process_set_contains_all(pset);		   \
		if (__all) {						   \
			__type = PIDTYPE_PID;				   \
			for_each_process(__p) {				   \
				struct nsproxy *__nsp;			   \
				__nsp = rcu_dereference(__p->nsproxy);	   \
				if (__nsp && __nsp->krg_ns) {		   \
					__pid = __p->pids[PIDTYPE_PID].pid;\
					goto __common_begin;		   \
				}					   \
			__all_end_of_loop:				   \
				continue;				   \
			}						   \
			break;						   \
		}							   \
		for (__type = 0; __type < PIDTYPE_MAX; __type++) {	   \
			__psubset = &(pset)->subsets[__type];		   \
			list_for_each_entry_rcu(__pset_el,		   \
						&__psubset->elements_head, \
						list) {			   \
				__pid = __pset_el->pid;			   \
			__common_begin:					   \
				do_each_pid_task(__pid, __type, p) {

/**
 * do {} while () style macro to end an iterating loop over the elements of a
 * process set
 * Arguments must be the same as for process_set_do_each_process()
 */
#define process_set_while_each_process(p, pset)				 \
				} while_each_pid_task(__pid, __type, p); \
				if (__all)				 \
					goto __all_end_of_loop;		 \
			}						 \
		}							 \
	} while (0)

/**
 * Cleanup all preparations done for process set iterations
 * Must be called after having finished iterating over a process set
 *
 * @param pset		process set to cleanup
 */
static inline void process_set_cleanup_do_each_process(struct process_set *pset)
{
	rcu_read_unlock();
}

/**
 * for (;;) like macro to iterate over all the process sets containing all
 * processes
 * caller must hold process_set_link_lock or RCU read lock
 *
 * @param pset		the process_set * to use as a loop cursor
 */
#define for_each_process_set_full(pset)			      \
	list_for_each_entry_rcu(pset,			      \
				&process_set_handle_all_head, \
				handle_all_list)

/**
 * do {} while () style macro to begin an iteration over the process sets
 * attached to a pid for a given pid_type
 * process sets attached to all processes must be parsed separately with
 * for_each_process_set_full().
 * caller must hold process_set_link_lock or RCU read lock
 *
 * @param pset		the process_set * to use as loop cursor
 * @param pid		the pid which process sets to iterate over
 * @param type	        pid_type for which process sets are attached to the pid
 */
#define do_each_process_set_pid(pset, pid, type)			      \
	do {								      \
		struct process_set_element *__pset_el;			      \
		struct hlist_node *__pos;				      \
		if (pid)						      \
			hlist_for_each_entry_rcu(__pset_el, __pos,	      \
						 &(pid)->process_sets[type],  \
						 pid_node) {		      \
				pset = container_of(			      \
					__pset_el->item.ci_parent->ci_parent, \
					struct process_set, group.cg_item);   \
				{

/**
 * do {} while () style macro to end an iteration over the process sets
 * attached to a pid for a given pid_type
 * Arguments must be the same as for do_each_process_set_pid()
 */
#define while_each_process_set_pid(pset, pid, type)			      \
				}					      \
			}						      \
	} while (0)

/**
 * do {} while () style macro to begin an iteration over the process sets
 * attached to a task
 * caller must either hold process_set_link_lock, and at least one of RCU and
 * tasklist_lock, or hold RCU read lock
 * process sets attached to all processes must be parsed separately with
 * for_each_process_set_full().
 * Note: process sets attached by several pid types will appear as many times.
 *
 * @param pset		the process_set * to use as loop cursor
 * @param task		task which attached process sets to iterate on
 */
#define do_each_process_set_task(pset, task)				     \
	do {								     \
		enum pid_type __type;					     \
		struct pid *__pid;					     \
		for (__type = PIDTYPE_PID; __type < PIDTYPE_MAX; __type++) { \
			__pid = rcu_dereference((task)->pids[__type].pid);   \
			do_each_process_set_pid(pset, __pid, __type) {

/**
 * do {} while () style macro to end an iteration over the process sets
 * attached to a task
 * Arguments must be the same as for do_each_process_set_task()
 */
#define while_each_process_set_task(pset, task)				     \
			} while_each_process_set_pid(pset, __pid, __type);   \
		}							     \
	} while(0)

#endif /* __KRG_SCHEDULER_PROCESS_SET__ */
