#ifndef __KERRIGHED_TASK_H__
#define __KERRIGHED_TASK_H__

#ifdef CONFIG_KRG_PROC

#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/kref.h>
#include <linux/rcupdate.h>
#include <kerrighed/sys/types.h>
#include <asm/cputime.h>

/** management of process than can or have migrated
 *  @author Geoffroy Vallee, David Margery, Pascal Gallard and Louis Rilling
 */

/* task kddm object */

struct task_struct;
struct pid;
#ifdef CONFIG_KRG_EPM
struct pid_kddm_object;
#endif

struct task_kddm_object {
	volatile long state;
	unsigned int flags;
	unsigned int ptrace;
	int exit_state;
	int exit_code, exit_signal;

	kerrighed_node_t node;
	u32 self_exec_id;
	int thread_group_empty;

	pid_t pid;
	pid_t parent;
	kerrighed_node_t parent_node;
	pid_t real_parent;
	pid_t real_parent_tgid;
	pid_t group_leader;

	uid_t uid;
	uid_t euid;
	gid_t egid;

	cputime_t utime, stime;

	unsigned int dumpable;

	/* The remaining fields are not shared */
#ifdef CONFIG_KRG_EPM
	struct pid_kddm_object *pid_obj;
#endif
	struct task_struct *task;

	struct rw_semaphore sem;
	unsigned write_locked:1;
	unsigned removing:1;

	unsigned alive:1;
	struct kref kref;

	struct rcu_head rcu;
};

void krg_task_get(struct task_kddm_object *obj);
void krg_task_put(struct task_kddm_object *obj);
int krg_task_alive(struct task_kddm_object *obj);
struct task_kddm_object *krg_task_readlock(pid_t pid);
struct task_kddm_object *__krg_task_readlock(struct task_struct *task);
struct task_kddm_object *krg_task_create_writelock(pid_t pid);
struct task_kddm_object *krg_task_writelock(pid_t pid);
struct task_kddm_object *__krg_task_writelock(struct task_struct *task);
struct task_kddm_object *krg_task_writelock_nested(pid_t pid);
struct task_kddm_object *__krg_task_writelock_nested(struct task_struct *task);
void krg_task_unlock(pid_t pid);
void __krg_task_unlock(struct task_struct *task);
int krg_task_alloc(struct task_struct *task, struct pid *pid);
void krg_task_fill(struct task_struct *task, unsigned long clone_flags);
void krg_task_commit(struct task_struct *task);
void krg_task_abort(struct task_struct *task);
#ifdef CONFIG_KRG_EPM
void __krg_task_free(struct task_struct *task);
#endif
void krg_task_free(struct task_struct *task);

/* exit */
#ifdef CONFIG_KRG_EPM
int krg_delay_release_task(struct task_struct *task);
#endif
void krg_release_task(struct task_struct *task);

void __krg_task_unlink(struct task_kddm_object *obj, int need_update);
void krg_task_unlink(struct task_kddm_object *obj, int need_update);

#endif /* CONFIG_KRG_PROC */

#endif /* __KERRIGHED_TASK_H__ */
