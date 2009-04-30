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

extern pid_t current_pid_mask;

/* No type checking, no current_pid_mask checking */
#define __MAKE_KERRIGHED_PID_FOR_NODE(pid, node) \
	(((node) << PID_NODE_SHIFT)|GLOBAL_PID_MASK|((pid) & INTERNAL_PID_MASK))

/* Same with checking */
static inline pid_t make_kerrighed_pid_for_node(pid_t pid,
						kerrighed_node_t node)
{
	pid_t ret;

	if (likely(current_pid_mask))
		ret = __MAKE_KERRIGHED_PID_FOR_NODE(pid, node);
	else
		ret = pid;

	return ret;

}

#define MAKE_KERRIGHED_PID_FOR_NODE(pid,node) \
	make_kerrighed_pid_for_node(pid, node)
#define MAKE_KERRIGHED_PID(pid) \
	MAKE_KERRIGHED_PID_FOR_NODE(pid,kerrighed_node_id)

/** extract the original linux kernel pid of a Kerrighed PID */
#define SHORT_PID(pid) ((pid) & INTERNAL_PID_MASK)
/** extract the original node id of a Kerrighed PID */
#define ORIG_NODE(pid) ((pid) >> PID_NODE_SHIFT)

#define KERRIGHED_PID_MAX_LIMIT \
	__MAKE_KERRIGHED_PID_FOR_NODE(0, KERRIGHED_MAX_NODES)

/* PID location */
#ifdef CONFIG_KRG_EPM
int krg_set_pid_location(pid_t pid, kerrighed_node_t node);
int krg_unset_pid_location(pid_t pid);
#endif
kerrighed_node_t krg_lock_pid_location(pid_t pid);
void krg_unlock_pid_location(pid_t pid);

#endif /* CONFIG_KRG_PROC */

#endif /* __KERRIGHED_PID_H__ */
