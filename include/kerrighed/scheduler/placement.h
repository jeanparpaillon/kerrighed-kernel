#ifndef __KRG_SCHEDULER_PLACEMENT_H__
#define __KRG_SCHEDULER_PLACEMENT_H__

#include <kerrighed/sys/types.h>

struct task_struct;

/**
 * Compute the "best" node on which a new task should be placed.
 * The node is chosen by asking to each scheduler attached to parent. Ties
 * are broken as described in placement.c
 *
 * @param parent	creator of the new task
 *
 * @return		a valid node id (at least when computed), or
 *			KERRIGHED_NODE_ID_NONE if no scheduler attached to
 *			parent cares
 */
kerrighed_node_t new_task_node(struct task_struct *parent);

#endif /* __KRG_SCHEDULER_PLACEMENT_H__ */
