#ifndef __TOOLS_PROCESS__
#define __TOOLS_PROCESS__

/** Make a process sleep and unlock.
 *
 *  @param q        Head of the wait queue to make the process sleep on.
 *  @param mutex    Mutex to unlock
 */
static inline void sleep_on_and_spin_unlock(wait_queue_head_t * wqh,
					    spinlock_t * mutex)
{
	wait_queue_t wait;

	init_waitqueue_entry(&wait, current);

	current->state = TASK_UNINTERRUPTIBLE;

#ifdef CONFIG_PREEMPT
	// The following code is not preempt save. Process can be preempted between
	// the insertion in the wait queue and the schedule.
	BUG();
#endif

	add_wait_queue(wqh, &wait);

	spin_unlock(mutex);

	schedule();

	remove_wait_queue(wqh, &wait);
}

#endif
