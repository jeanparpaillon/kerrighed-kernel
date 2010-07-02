#ifndef __KERRIGHED_PID_H__
#define __KERRIGHED_PID_H__

#ifdef CONFIG_KRG_PROC

#include <asm/page.h> /* Needed by linux/threads.h */
#include <linux/pid_namespace.h>
#include <linux/threads.h>
#include <linux/types.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/krgnodemask.h>

/*
 * WARNING: procfs and futex need at least the 2 MSbits free (in procfs: 1 for
 * sign, 1 for upper pid limit; in futex: see linux/futex.h)
 */

#define GLOBAL_PID_MASK PID_MAX_LIMIT
#define PID_NODE_SHIFT (NR_BITS_PID_MAX_LIMIT + 1)
#define INTERNAL_PID_MASK (PID_MAX_LIMIT - 1)

#define GLOBAL_PID_NODE(pid, node) \
	(((node) << PID_NODE_SHIFT)|GLOBAL_PID_MASK|((pid) & INTERNAL_PID_MASK))
#define GLOBAL_PID(pid) GLOBAL_PID_NODE(pid, kerrighed_node_id)

/** extract the original linux kernel pid of a Kerrighed PID */
#define SHORT_PID(pid) ((pid) & INTERNAL_PID_MASK)
/** extract the original node id of a Kerrighed PID */
#define ORIG_NODE(pid) ((pid) >> PID_NODE_SHIFT)

#define KERRIGHED_PID_MAX_LIMIT GLOBAL_PID_NODE(0, KERRIGHED_MAX_NODES)

/* Kerrighed container's PID numbers */
static inline pid_t pid_knr(struct pid *pid)
{
	struct pid_namespace *ns = ns_of_pid(pid);
	if (ns && ns->krg_ns)
		return pid_nr_ns(pid, krg_pid_ns_root(ns));
	return 0;
}

static inline pid_t task_pid_knr(struct task_struct *task)
{
	return pid_knr(task_pid(task));
}

static inline pid_t task_tgid_knr(struct task_struct *task)
{
	return pid_knr(task_tgid(task));
}

static inline pid_t task_pgrp_knr(struct task_struct *task)
{
	return pid_knr(task_pgrp(task));
}

static inline pid_t task_session_knr(struct task_struct *task)
{
	return pid_knr(task_session(task));
}

static inline struct pid *find_kpid(int nr)
{
	struct pid_namespace *ns = find_get_krg_pid_ns();
	struct pid *pid = find_pid_ns(nr, ns);
	put_pid_ns(ns);
	return pid;
}

static inline struct task_struct *find_task_by_kpid(pid_t pid)
{
	return pid_task(find_kpid(pid), PIDTYPE_PID);
}

/* PID location */
#ifdef CONFIG_KRG_EPM
void __krg_set_pid_location(struct task_struct *task);
int krg_set_pid_location(struct task_struct *task);
void __krg_unset_pid_location(struct task_struct *task);
int krg_unset_pid_location(struct task_struct *task);
#endif
kerrighed_node_t krg_lock_pid_location(pid_t pid);
void krg_unlock_pid_location(pid_t pid);

/* Global PID, foreign pidmap aware iterator */
struct pid *krg_find_ge_pid(int nr, struct pid_namespace *pid_ns,
			    struct pid_namespace *pidmap_ns);

#else /* !CONFIG_KRG_PROC */

static inline pid_t pid_knr(struct pid *pid)
{
	return pid_nr(pid);
}

static
inline pid_t __task_pid_knr(struct task_struct *task, enum pid_type type)
{
	return __task_pid_nr_ns(task, type, &init_pid_ns);
}

static inline pid_t task_pid_knr(struct task_struct *task)
{
	return task->pid;
}

static inline pid_t task_tgid_knr(struct task_struct *task)
{
	return task->tgid;
}

static inline pid_t task_pgrp_knr(struct task_struct *task)
{
	return __task_pid_knr(task, PIDTYPE_PGID);
}

static inline pid_t task_session_knr(struct task_struct *task)
{
	return __task_pid_knr(task, PIDTYPE_SID);
}

static inline struct pid *find_kpid(int nr)
{
	return find_pid_ns(nr, &init_pid_ns);
}

static inline struct task_struct *find_task_by_kpid(pid_t pid)
{
	return find_task_by_pid_ns(pid, &init_pid_ns);
}

#endif /* !CONFIG_KRG_PROC */

#ifdef CONFIG_KRG_EPM

/* Task KDDM object link */
struct pid_kddm_object;
struct task_kddm_object;
struct pid;

/* Must be called under rcu_read_lock() */
struct task_kddm_object *krg_pid_task(struct pid *pid);

/* Must be called under rcu_read_lock() */
void krg_pid_unlink_task(struct pid_kddm_object *obj);

/* Pid reference tracking */
struct pid *krg_get_pid(int nr);
void krg_end_get_pid(struct pid *pid);
void krg_put_pid(struct pid *pid);

/* Foreign pidmaps */
int pidmap_map_read_lock(void);
void pidmap_map_read_unlock(void);
kerrighed_node_t pidmap_node(kerrighed_node_t node);
struct pid_namespace *node_pidmap(kerrighed_node_t node);

void pidmap_map_cleanup(struct krg_namespace *krg_ns);

void krg_free_pidmap(struct upid *upid);

#elif defined(CONFIG_KRG_PROC)

static inline int pidmap_map_read_lock(void)
{
	return 0;
}

static inline void pidmap_map_read_unlock(void)
{
}

static inline kerrighed_node_t pidmap_node(kerrighed_node_t node)
{
	return krgnode_online(node) ? node : KERRIGHED_NODE_ID_NONE;
}

static inline struct pid_namespace *node_pidmap(kerrighed_node_t node)
{
	return NULL;
}

#endif /* CONFIG_KRG_EPM */

#endif /* __KERRIGHED_PID_H__ */
