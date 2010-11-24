/*
 *  kerrighed/proc/libproc.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 */

#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/pid.h>
#include <kddm/io_linker.h>

/* Generic function to assign a default owner to a pid-named kddm object */
kerrighed_node_t global_pid_default_owner(struct kddm_set *set, objid_t objid,
					  const krgnodemask_t *nodes,
					  int nr_nodes)
{
	kerrighed_node_t node;

	BUG_ON(!(objid & GLOBAL_PID_MASK));
	node = ORIG_NODE(objid);
	if (node < 0 || node >= KERRIGHED_MAX_NODES)
		/* Invalid ID */
		node = kerrighed_node_id;
	if (!__krgnode_isset(node, nodes))
		node = __next_krgnode_in_ring(node, nodes);
	return node;
}
