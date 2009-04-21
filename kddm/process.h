#ifndef __TOOLS_PROCESS__
#define __TOOLS_PROCESS__

#define task_on_runqueue(t) (t->run_list.next != LIST_POISON1)


/** Make a process sleep
 *
 *  @param task  Task struct of the process
 */
static inline void sleep_on_task(struct task_struct *task)
{
	set_task_state(task, TASK_UNINTERRUPTIBLE);
#ifdef SLEEP_ON_GENERIC_TASK
	if (task != current && task_on_runqueue(task)) {
		spin_lock_irq(&runqueue_lock);
		del_from_runqueue(task);
		spin_unlock_irq(&runqueue_lock);
	}
#else
	if (task != current) {
		printk("%s: task != current\n", __PRETTY_FUNCTION__);
		while (1)
			schedule();
	}
#endif
	schedule();
}


/** Make a process sleep
 *
 *  @param task  Task struct of the process
 */
static inline void interruptible_sleep_on_task(struct task_struct *task)
{
	set_task_state(task, TASK_INTERRUPTIBLE);
#ifdef SLEEP_ON_GENERIC_TASK
	if (task != current && task_on_runqueue(task)) {
		spin_lock_irq(&runqueue_lock);
		del_from_runqueue(task);
		spin_unlock_irq(&runqueue_lock);
	}
#else
	if (task != current) {
		printk("%s: task != current\n", __PRETTY_FUNCTION__);
		while (1)
			schedule();
	}
#endif
	schedule();
}


/** Make a process sleep, unlock and restore IRQs.
 *
 *  @param task   Task struct of the process
 *  @param mutex  Mutex to unlock
 *  @param flafs  Flags of the IRQ to restore.
 */
static inline void
sleep_on_task_and_spin_unlock_irqrestore(struct task_struct *task,
					 spinlock_t *mutex,
					 unsigned long flags)
{
	set_task_state(task, TASK_UNINTERRUPTIBLE);
#ifdef SLEEP_ON_GENERIC_TASK
	if (task != current && task_on_runqueue(task)) {
		spin_lock(&runqueue_lock);
		del_from_runqueue(task);
		spin_unlock(&runqueue_lock);
	}
#else
	if (task != current) {
		printk("%s: task != current\n", __PRETTY_FUNCTION__);
		while (1)
			schedule();
	}
#endif

	spin_unlock_irqrestore(mutex, flags);
	schedule();
}


/** Make a process sleep, unlock and restore soft IRQs.
 *
 *  @param task   Task struct of the process
 *  @param mutex  Mutex to unlock
 */
static inline void sleep_on_task_and_spin_unlock_bh(struct task_struct *task,
						    spinlock_t * mutex)
{
	set_task_state(task, TASK_UNINTERRUPTIBLE);
#ifdef SLEEP_ON_GENERIC_TASK
	if (task != current && task_on_runqueue(task)) {
		spin_lock(&runqueue_lock);
		del_from_runqueue(task);
		spin_unlock(&runqueue_lock);
	}
#else
	if (task != current) {
		printk("%s: task != current\n", __PRETTY_FUNCTION__);
		while (1)
			schedule();
	}
#endif

	spin_unlock_bh(mutex);
	schedule();
}


/** Make a process sleep, unlock and restore soft IRQs.
 *
 *  @param task   Task struct of the process
 *  @param mutex  Mutex to unlock
 */
static inline void
interruptible_sleep_on_task_and_spin_unlock_bh(struct task_struct *task,
					       spinlock_t *mutex)
{
	set_task_state(task, TASK_INTERRUPTIBLE);
#ifdef SLEEP_ON_GENERIC_TASK
	if (task != current && task_on_runqueue(task)) {
		spin_lock(&runqueue_lock);
		del_from_runqueue(task);
		spin_unlock(&runqueue_lock);
	}
#else
	if (task != current) {
		printk("%s: task != current\n", __PRETTY_FUNCTION__);
		while (1)
			schedule();
	}
#endif

	spin_unlock_bh(mutex);
	schedule();
}


/** Make a process sleep for a given amount of time on an wait queue,
 *  unlock and restore soft IRQs.
 *
 *  @param wqh      Head of the wait queue to make the process sleep on.
 *  @param tsk      Task struct of the process to sleep on.
 *  @param timeout  Maximum amount of time to sleep (in jiffies).
 *  @param mutex    Mutex to unlock
 */
static inline long sleep_on_timeout_and_spin_unlock_bh(wait_queue_head_t *wqh,
						       struct task_struct *task,
						       unsigned long timeout,
						       spinlock_t *mutex)
{
	wait_queue_t wait;

	init_waitqueue_entry(&wait, task);

#ifdef CONFIG_PREEMPT
	/* The following code is not preempt save. Process can be preempted
	 * between the insertion in the wait queue and the schedule. */
	BUG();
#endif

	add_wait_queue(wqh, &wait);

	set_task_state(task, TASK_UNINTERRUPTIBLE);
#ifdef SLEEP_ON_GENERIC_TASK
	if (task != current && task_on_runqueue(task)) {
		spin_lock(&runqueue_lock);
		del_from_runqueue(task);
		spin_unlock(&runqueue_lock);
	}
#else
	if (task != current) {
		printk("%s: task != current\n", __PRETTY_FUNCTION__);
		while (1)
			schedule();
	}
#endif

	spin_unlock_bh(mutex);

	timeout = schedule_timeout(timeout);

	remove_wait_queue(wqh, &wait);

	return timeout;
}


/** Make a process sleep, unlock and restore soft IRQs.
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


/** Make a process sleep on an exclusive wait queue,
 *  unlock and restore soft IRQs.
 *
 *  @param wqh    Head of the wait queue to make the process sleep on.
 *  @param tsk    Task struct of the process to sleep on.
 *  @param mutex  Mutex to unlock
 */
static inline void sleep_on_exclusive_and_spin_unlock_bh(wait_queue_head_t *
							 wqh,
							 struct task_struct
							 *tsk,
							 spinlock_t * mutex)
{
	wait_queue_t wait;

	init_waitqueue_entry(&wait, tsk);

	add_wait_queue_exclusive(wqh, &wait);

	sleep_on_task_and_spin_unlock_bh(tsk, mutex);

	remove_wait_queue(wqh, &wait);
}

/** Make a process sleep on an exclusive wait queue,
 *  unlock and restore soft IRQs.
 *
 *  @param wqh    Head of the wait queue to make the process sleep on.
 *  @param tsk    Task struct of the process to sleep on.
 *  @param mutex  Mutex to unlock
 */
static inline void
interruptible_sleep_on_exclusive_and_spin_unlock_bh(wait_queue_head_t * wqh,
						    struct task_struct *tsk,
						    spinlock_t * mutex)
{
	wait_queue_t wait;

	init_waitqueue_entry(&wait, tsk);

	add_wait_queue_exclusive(wqh, &wait);

	interruptible_sleep_on_task_and_spin_unlock_bh(tsk, mutex);

	remove_wait_queue(wqh, &wait);
}

/** Make a process sleep for a given amount of time on an exclusive wait
 *  queue, unlock and restore soft IRQs.
 *
 *  @param wqh      Head of the wait queue to make the process sleep on.
 *  @param tsk      Task struct of the process to sleep on.
 *  @param timeout  Maximum amount of time to sleep (in jiffies).
 *  @param mutex    Mutex to unlock
 */
static inline long
sleep_on_timeout_exclusive_and_spin_unlock_bh(wait_queue_head_t * wqh,
					      struct task_struct *tsk,
					      unsigned long timeout,
					      spinlock_t * mutex)
{
	return sleep_on_timeout_and_spin_unlock_bh(wqh, tsk, timeout, mutex);
}


/** Make the current process sleep for a given number of seconds.
 *
 *  @param seconds   The number of seconds the process should sleep
 */
static inline void sleep(int seconds)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(seconds * HZ);
}

#endif
