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
	APP_FROZEN,
	APP_RESTARTED,
	APP_RUNNING,
	APP_RUNNING_CS /* Application is running but is in a critical section:
			* Checkpoint is forbidden. */
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

	spinlock_t lock;
	struct completion tasks_chkpted;

	/* local processes of the application */
	struct list_head tasks;

	/* list of structs shared by those processes */
	/* MUST be empty when no checkpoint is in progress */
	struct {
		struct rb_root root;
		spinlock_t lock;
	} shared_objects;

	union {
		struct {
			char *storage_dir;
			int flags;

			struct cr_mm_region *first_mm_region;
		} checkpoint;

		struct {
			const char *storage_dir;
			krgnodemask_t replacing_nodes;
		} restart;
	};

	const struct cred *cred;
};

/*--------------------------------------------------------------------------*/

int create_application(struct task_struct *task);

struct app_struct *new_local_app(long app_id);

void delete_app(struct app_struct *app);

int __delete_local_app(struct app_struct *app);

struct app_struct *find_local_app(long app_id);

/*--------------------------------------------------------------------------*/

task_state_t *alloc_task_state_from_pids(pid_t pid,
					  pid_t tgid,
					  pid_t parent,
					  pid_t real_parent,
					  pid_t real_parent_tgid,
					  pid_t pgrp,
					  pid_t session);

void free_task_state(task_state_t *t);

int register_task_to_appid(long app_id, struct task_struct *task);

int register_task_to_app(struct app_struct *app, struct task_struct *task);

void unregister_task_to_app(struct app_struct *app, struct task_struct *task);

/* need to hold lock app->lock before calling it */
static inline int local_tasks_list_empty(struct app_struct *app) {
	return list_empty(&app->tasks);
}

void set_task_chkpt_result(struct task_struct *task, int result);
int get_local_tasks_chkpt_result(struct app_struct* app);

/*--------------------------------------------------------------------------*/

int krg_copy_application(struct task_struct *task);
void krg_exit_application(struct task_struct *task);

/*--------------------------------------------------------------------------*/

int export_application(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task);
int import_application(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task);
void unimport_application(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task);

/*--------------------------------------------------------------------------*/

int global_stop(struct app_kddm_object *obj);

int global_unfreeze(struct app_kddm_object *obj, int signal);

/*--------------------------------------------------------------------------*/

int app_set_userdata(__u64 user_data);

int app_get_userdata(long _appid, int flags, __u64 *user_data);

int app_cr_disable(void);

int app_cr_enable(void);

/*--------------------------------------------------------------------------*/

void application_cr_server_init(void);
void application_cr_server_finalize(void);

#endif /* CONFIG_KRG_EPM */

#endif /* __APPLICATION_H__ */
