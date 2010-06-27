#ifndef __KRG_CHILDREN_H__
#define __KRG_CHILDREN_H__

#ifdef CONFIG_KRG_EPM

#include <linux/types.h>
#include <kerrighed/sys/types.h>

struct children_kddm_object;
struct task_struct;
struct pid_namespace;
struct pid;

struct children_kddm_object *krg_children_alloc(struct task_struct *task);
void krg_children_share(struct task_struct *task);
void krg_children_exit(struct task_struct *task);
void krg_children_get(struct children_kddm_object *obj);
void krg_children_put(struct children_kddm_object *obj);
int krg_new_child(struct children_kddm_object *obj,
		  pid_t parent_pid,
		  struct task_struct *child);
void __krg_set_child_pgid(struct children_kddm_object *obj,
			  pid_t pid, pid_t pgid);
void krg_set_child_pgid(struct children_kddm_object *obj,
			struct task_struct *child);
int krg_set_child_ptraced(struct children_kddm_object *obj,
			  struct task_struct *child, int ptraced);
void krg_set_child_exit_signal(struct children_kddm_object *obj,
			       struct task_struct *child);
void krg_set_child_exit_state(struct children_kddm_object *obj,
			      struct task_struct *child);
void krg_remove_child(struct children_kddm_object *obj,
		      struct task_struct *child);
void krg_forget_original_remote_parent(struct task_struct *parent,
				       struct task_struct *reaper);
pid_t krg_get_real_parent_tgid(struct task_struct *task,
			       struct pid_namespace *ns);
pid_t krg_get_real_parent_pid(struct task_struct *task);
int __krg_get_parent(struct children_kddm_object *obj, pid_t pid,
		     pid_t *parent_pid, pid_t *real_parent_pid);
int krg_get_parent(struct children_kddm_object *obj, struct task_struct *child,
		     pid_t *parent_pid, pid_t *real_parent_pid);
struct children_kddm_object *krg_children_writelock(pid_t tgid);
struct children_kddm_object *__krg_children_writelock(struct task_struct *task);
struct children_kddm_object *krg_children_writelock_nested(pid_t tgid);
struct children_kddm_object *krg_children_readlock(pid_t tgid);
struct children_kddm_object *__krg_children_readlock(struct task_struct *task);
struct children_kddm_object *
krg_parent_children_writelock(struct task_struct *task);
struct children_kddm_object *
krg_parent_children_readlock(struct task_struct *task);
void krg_children_unlock(struct children_kddm_object *obj);
void krg_update_self_exec_id(struct task_struct *task);
u32 krg_get_real_parent_self_exec_id(struct task_struct *task,
				     struct children_kddm_object *obj);

/* fork() hooks */
int krg_children_prepare_fork(struct task_struct *task,
			      struct pid *pid,
			      unsigned long clone_flags);
int krg_children_fork(struct task_struct *task,
		      struct pid *pid,
		      unsigned long clone_flags);
void krg_children_commit_fork(struct task_struct *task);
void krg_children_abort_fork(struct task_struct *task);

/* exit()/release_task() hooks */
void krg_reparent_to_local_child_reaper(struct task_struct *task);
void krg_children_cleanup(struct task_struct *task);

/* de_thread() hooks */
struct children_kddm_object *
krg_children_prepare_de_thread(struct task_struct *task);
void krg_children_finish_de_thread(struct children_kddm_object *obj,
				   struct task_struct *task);

/* Used by krg_prepare_exit_notify() and krg_delayed_notify_parent() */
void krg_update_parents(struct task_struct *task,
			struct children_kddm_object *parent_children_obj,
			pid_t parent, pid_t real_parent,
			kerrighed_node_t node);
/* Used by krg_release_task() */
void krg_unhash_process(struct task_struct *tsk);

#endif /* CONFIG_KRG_EPM */

#endif /* __KRG_CHILDREN_H__ */
