#ifndef __KERRIGHED_PID_H__
#define __KERRIGHED_PID_H__

#ifdef CONFIG_KRG_PROC

#include <asm/page.h> /* Needed by linux/threads.h */
#include <linux/pid_namespace.h>
#include <linux/threads.h>
#include <linux/types.h>
#include <kerrighed/sys/types.h>

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

/* PID location */
#ifdef CONFIG_KRG_EPM
int krg_set_pid_location(pid_t pid, kerrighed_node_t node);
int krg_unset_pid_location(pid_t pid);
#endif
kerrighed_node_t krg_lock_pid_location(pid_t pid);
void krg_unlock_pid_location(pid_t pid);

#endif /* CONFIG_KRG_PROC */

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
void krg_put_pid(struct pid *pid);

#endif /* CONFIG_KRG_EPM */

#endif /* __KERRIGHED_PID_H__ */
