/*
 *  kerrighed/epm/action.c
 *
 *  Copyright (C) 2006-2007 Louis Rilling - Kerlabs
 */
/*
 * Management of incompatibilities between Kerrighed actions and
 * some Linux facilities
 */

#include <linux/sched.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>
#include <kerrighed/capabilities.h>
#include <kerrighed/action.h>

static int action_to_cap_mapping[] = {
	[EPM_MIGRATE] = CAP_CAN_MIGRATE,
	[EPM_REMOTE_CLONE] = CAP_DISTANT_FORK,
	[EPM_CHECKPOINT] = CAP_CHECKPOINTABLE,
};

DEFINE_RWLOCK(krg_action_lock);

char *__krg_action_to_str(krg_epm_action_t action)
{
	static char *migration_str = "migration";
	static char *remote_fork_str = "remote fork";
	static char *checkpoint_str = "checkpoint";
	static char *restart_str = "restart";
	char *action_str;

	switch(action) {
	case EPM_MIGRATE:
		action_str = migration_str;
		break;
	case EPM_REMOTE_CLONE:
		action_str = remote_fork_str;
		break;
	case EPM_CHECKPOINT:
		action_str = checkpoint_str;
		break;
	case EPM_RESTART:
		action_str = restart_str;
		break;
	default:
		BUG();
		action_str = NULL;
	}

	return action_str;
}

static inline void action_lock_lock(void)
{
	lockdep_off();
	write_lock(&krg_action_lock);
}

static inline void action_lock_unlock(void)
{
	write_unlock(&krg_action_lock);
	lockdep_on();
}

static inline int action_to_flag(krg_epm_action_t action)
{
	if (unlikely(action <= EPM_NO_ACTION || action >= EPM_ACTION_MAX))
		return 0;
	else
		return 1 << action;
}

static inline int action_to_cap(krg_epm_action_t action)
{
	if (unlikely(action <= EPM_NO_ACTION || action >= EPM_ACTION_MAX))
		return -1;
	else
		return action_to_cap_mapping[action];
}

int krg_action_disable(struct task_struct *task, krg_epm_action_t action,
		       int inheritable)
{
	unsigned long flag;
	int retval = 0;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return -EINVAL;

	action_lock_lock();
	if (unlikely(task->krg_action_flags & flag))
		retval = -EAGAIN;
	else {
		atomic_t *array;

		if (inheritable)
			array = task->krg_cap_unavailable;
		else
			array = task->krg_cap_unavailable_private;
		atomic_inc(&array[action_to_cap(action)]);
	}
	action_lock_unlock();

	return retval;
}

int krg_action_enable(struct task_struct *task, krg_epm_action_t action,
		      int inheritable)
{
	atomic_t *array;
	int cap;

	cap = action_to_cap(action);
	if (unlikely(cap < 0))
		return -EINVAL;

	if (inheritable)
		array = task->krg_cap_unavailable;
	else
		array = task->krg_cap_unavailable_private;
	if (unlikely(atomic_add_negative(-1, &array[cap])))
		BUG();

	return 0;
}

int krg_action_start(struct task_struct *task, krg_epm_action_t action)
{
	unsigned long flag;
	int retval = 0;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return -EINVAL;

	action_lock_lock();
	if (!can_use_krg_cap(task, action_to_cap(action)))
		retval = -EPERM;
	else if (unlikely(task->krg_action_flags & flag))
		retval = -EALREADY;
	else if (unlikely(task->krg_action_flags))
		retval = -EAGAIN;
	else
		task->krg_action_flags |= flag;
	action_lock_unlock();

	return retval;
}

int krg_action_stop(struct task_struct *task, krg_epm_action_t action)
{
	unsigned long flag;
	int retval = 0;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return -EINVAL;

	action_lock_lock();
	task->krg_action_flags &= ~flag;
	action_lock_unlock();

	return retval;
}

int krg_action_pending(struct task_struct *task, krg_epm_action_t action)
{
	unsigned long flag;
	int retval;

	flag = action_to_flag(action);
	if (unlikely(!flag))
		return 0;

	action_lock_lock();
	retval = task->krg_action_flags & flag;
	action_lock_unlock();

	return retval;
}
