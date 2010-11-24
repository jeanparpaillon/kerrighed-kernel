/*
 * Management of incompatibilities between Kerrighed actions and
 * some Linux facilities
 */

#ifndef __KRG_ACTION_H__
#define __KRG_ACTION_H__

#ifdef CONFIG_KRG_EPM

#include <linux/sched.h>
#include <linux/time.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/sys/checkpoint.h>

typedef enum {
	EPM_NO_ACTION,
	EPM_MIGRATE,
	EPM_REMOTE_CLONE,
	EPM_CHECKPOINT,
	EPM_RESTART, /* Never used in krg_action_start/stop */
	EPM_ACTION_MAX	   /* Always in last position */
} krg_epm_action_t;

typedef enum {
	CR_SAVE_NOW,
	CR_SAVE_LATER
} c_shared_obj_option_t;

typedef enum {
	CR_LOAD_NOW,
	CR_LINK_ONLY
} r_shared_obj_option_t;

#define APP_REPLACE_PGRP	1
#define APP_REPLACE_SID		2

struct task_struct;
struct completion;

struct epm_action {
	krg_epm_action_t type;
	union {
		struct {
			pid_t pid;
			kerrighed_node_t source;
			kerrighed_node_t target;
			struct timespec start_date;
			struct timespec end_date;
		} migrate;
		struct {
			pid_t from_pid;
			pid_t from_tgid;
			kerrighed_node_t target;
			unsigned long clone_flags;
			unsigned long stack_start;
			unsigned long stack_size;
			int *parent_tidptr;
			int *child_tidptr;
			struct completion *vfork;
		} remote_clone;
		struct {
			long appid;
			c_shared_obj_option_t shared;
		} checkpoint;
		struct {
			long appid;
			r_shared_obj_option_t shared;
			struct app_struct * app;
			int flags;
		} restart;
	};
};

static inline kerrighed_node_t epm_target_node(struct epm_action *action)
{
	switch (action->type) {
	case EPM_MIGRATE:
		return action->migrate.target;
	case EPM_REMOTE_CLONE:
		return action->remote_clone.target;
	case EPM_CHECKPOINT:
	case EPM_RESTART:
		return KERRIGHED_NODE_ID_NONE;
	default:
		BUG();
	}
}

char *__krg_action_to_str(krg_epm_action_t action);

static inline char *krg_action_to_str(struct epm_action *action)
{
	return __krg_action_to_str(action->type);
}

/*
 * Nests inside and outside of read_lock(&taskslist_lock), but neither inside
 * nor outside write_lock(_irq)(&tasklist_lock).
 * Nests outside sighand->lock.
 */
extern rwlock_t krg_action_lock;

static inline void krg_action_block_all(void)
{
	read_lock(&krg_action_lock);
}

static inline void krg_action_unblock_all(void)
{
	read_unlock(&krg_action_lock);
}

static inline int krg_action_any_pending(struct task_struct *task)
{
	return task->krg_action_flags;
}

static inline int krg_action_block_any(struct task_struct *task)
{
	int pending;

	krg_action_block_all();
	pending = krg_action_any_pending(task);
	if (pending)
		krg_action_unblock_all();
	return !pending;
}

static inline void krg_action_unblock_any(struct task_struct *task)
{
	krg_action_unblock_all();
}

int krg_action_disable(struct task_struct *task, krg_epm_action_t action,
		       int inheritable);
int krg_action_enable(struct task_struct *task, krg_epm_action_t action,
		      int inheritable);

int krg_action_start(struct task_struct *task, krg_epm_action_t action);
int krg_action_stop(struct task_struct *task, krg_epm_action_t action);

int krg_action_pending(struct task_struct *task, krg_epm_action_t action);

#endif /* CONFIG_KRG_EPM */

#endif /* __KRG_ACTION_H__ */
