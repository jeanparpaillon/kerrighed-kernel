/** Application
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#ifdef CONFIG_KRG_EPM

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/completion.h>
#include <linux/rbtree.h>

#include <kerrighed/sys/types.h>
#include <kerrighed/types.h>

#include <kerrighed/sys/checkpoint.h>
#include <kerrighed/ghost.h>
#include <kerrighed/action.h>

struct rpc_desc;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              STRUCTURES                                  *
 *                                                                          *
 *--------------------------------------------------------------------------*/

enum {
	PCUS_OPERATION_OK,
	PCUS_STOP_IN_PROGRESS,
	PCUS_CHKPT_IN_PROGRESS,
	PCUS_RUNNING
};

struct credentials {
	uid_t uid;
	uid_t euid;
	gid_t gid;
};

typedef struct task_identity {
	pid_t pid;
	pid_t tgid;
} task_identity_t;

typedef struct task_and_state {

	struct task_struct *task;
	union {
		struct {
			pid_t pid;
			pid_t tgid;
			pid_t parent;
			pid_t real_parent;
			pid_t real_parent_tgid;

			pid_t pgrp;
			pid_t session;
		} restart;
	};
	int chkpt_result;
	struct list_head next_task;
} task_state_t;

typedef enum {
	FROZEN,
	RUNNING
} app_state_t;

struct app_kddm_object {
	long app_id;
	int chkpt_sn;

	app_state_t state;
	krgnodemask_t nodes;

	__u64 user_data;
};

struct app_struct {
	long app_id;
	int chkpt_sn;

	spinlock_t lock;
	struct completion tasks_chkpted;

	/* local processes of the application */
	struct list_head tasks;

	/* list of structs shared by those processes */
	/* MUST be empty when no checkpoint is in progress */
	struct rb_root shared_objects;

	union {
		struct {
			struct file *terminal;
		} checkpoint;

		struct {
			struct file *terminal;
		} restart;
	};
};

#endif /* CONFIG_KRG_EPM */

#endif /* __APPLICATION_H__ */
