#ifndef __KRGINIT_H__
#define __KRGINIT_H__

#include <kerrighed/types.h>
#include <linux/rwsem.h>

enum kerrighed_init_flags_t {
	KRG_INITFLAGS_NODEID,
	KRG_INITFLAGS_SESSIONID,
	KRG_INITFLAGS_AUTONODEID,
};

/* Tools */
extern kerrighed_node_t kerrighed_node_id;
extern kerrighed_node_t kerrighed_nb_nodes;
extern kerrighed_node_t kerrighed_nb_nodes_min;
extern kerrighed_session_t kerrighed_session_id;
extern kerrighed_subsession_t kerrighed_subsession_id;
extern int kerrighed_init_flags;
extern struct rw_semaphore kerrighed_init_sem;

#define SET_KRG_INIT_FLAGS(p) kerrighed_init_flags |= (1<<p)
#define CLR_KRG_INIT_FLAGS(p) kerrighed_init_flags &= ~(1<<p)
#define ISSET_KRG_INIT_FLAGS(p) (kerrighed_init_flags & (1<<p))

#endif
