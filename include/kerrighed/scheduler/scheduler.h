#ifndef __KRG_SCHEDULER_SCHEDULER_H__
#define __KRG_SCHEDULER_SCHEDULER_H__

#include <kerrighed/scheduler/process_set.h>

struct scheduler_policy;
struct scheduler;

/**
 * Get a reference on a scheduler
 *
 * @param scheduler	scheduler to get a reference on
 */
void scheduler_get(struct scheduler *scheduler);
/**
 * Put a reference on a scheduler
 *
 * @param scheduler	scheduler to put a reference on
 */
void scheduler_put(struct scheduler *scheduler);

/**
 * Get a reference on the scheduler owning a scheduler_policy
 * The reference must be put with scheduler_put()
 *
 * @param policy	scheduling policy of the searched scheduler
 *
 * @return		scheduler owning the scheduler_policy, or
 *			NULL if the scheduler_policy is not used anymore
 */
struct scheduler *
scheduler_policy_get_scheduler(struct scheduler_policy *policy);

/**
 * Get a reference on the scheduler owning a process set
 * The reference must be put with scheduler_put()
 *
 * @param pset		process set of the searched scheduler
 *
 * @return		scheduler owning the process set
 */
struct scheduler *process_set_get_scheduler(struct process_set *pset);

/**
 * Get a reference on the sched policy of a scheduler
 * The reference must be put with scheduler_policy_put()
 *
 * @param scheduler	scheduler which sched policy to get
 *
 * @return		sched policy of the scheduler
 */
struct scheduler_policy *
scheduler_get_scheduler_policy(struct scheduler *scheduler);

/**
 * Get a reference on the process set managed by a scheduler
 * The reference must be put with process_set_put()
 *
 * @param scheduler	scheduler to get the process set of
 *
 * @return		process set of the scheduler, or
 *			NULL if the scheduler is not active anymore
 */
struct process_set *scheduler_get_process_set(struct scheduler *scheduler);

/**
 * Get the current node set of the scheduler
 *
 * @param scheduler	scheduler which node set to get
 * @param node_set	node_set to copy the scheduler's node set in
 */
void scheduler_get_node_set(struct scheduler *scheduler,
			    krgnodemask_t *node_set);

/**
 * do {} while () style macro to begin an iteration over all universal
 * schedulers (that is set to handle all processes)
 *
 * @param scheduler	the scheduler * to use as a loop cursor
 */
#define do_each_scheduler_universal(scheduler)			       \
	do {							       \
		struct process_set *__pset;			       \
		for_each_process_set_full(__pset) {		       \
			scheduler = process_set_get_scheduler(__pset); \
			if (scheduler) {			       \
				do {

/**
 * do {} while () style macro to end an iteration over all universal
 * schedulers (that is set to handle all processes)
 * Arguments must be the same as for do_each_scheduler_universal()
 */
#define while_each_scheduler_universal(scheduler)		       \
				} while (0);			       \
				scheduler_put(scheduler);	       \
			}					       \
		}						       \
	} while (0)

/**
 * do {} while () style macro to begin an iteration over the schedulers managing
 * a task
 * Schedulers attached to all tasks have to be separately parsed with
 * do_each_scheduler_universal()
 * caller must hold either RCU lock or tasklist_lock
 *
 * @param scheduler	the scheduler * to use a loop cursor
 * @param task		task which schedulers to iterate over
 */
#define do_each_scheduler_task(scheduler, task)			       \
	do {							       \
		struct process_set *__pset;			       \
		do_each_process_set_task(__pset, task) {	       \
			scheduler = process_set_get_scheduler(__pset); \
			if (scheduler) {			       \
				do {

/**
 * do {} while () style macro to end an iteration over the schedulers managing
 * a task
 * Arguments must be the same as for do_each_scheduler_task()
 */
#define while_each_scheduler_task(scheduler, task)		       \
				} while (0);			       \
				scheduler_put(scheduler);	       \
			}					       \
		} while_each_process_set_task(__pset, task);	       \
	} while (0)

#endif /* __KRG_SCHEDULER_SCHEDULER_H__ */
