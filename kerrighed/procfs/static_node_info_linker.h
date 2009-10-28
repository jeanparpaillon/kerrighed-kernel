/** Static node informations management.
 *  @file static_node_info_linker.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef STATIC_NODE_INFO_LINKER_H
#define STATIC_NODE_INFO_LINKER_H

#include <kddm/kddm.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Static node informations */

typedef struct {
	int nr_cpu;		/* Number of CPU on the node */
	unsigned long totalram;	/* Total usable main memory size */
	unsigned long totalhigh;	/* Total high memory size */
} krg_static_node_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct kddm_set *static_node_info_kddm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int static_node_info_init(void);

/** Helper function to get static node informations.
 *  @author Renaud Lottiaux
 *
 *  @param node_id   Id of the node we want informations on.
 *
 *  @return  Structure containing information on the requested node.
 */
static inline krg_static_node_info_t *get_static_node_info(int node_id)
{
	return _kddm_get_object_no_lock(static_node_info_kddm_set, node_id);
}

kerrighed_node_t node_info_default_owner(struct kddm_set *set,
					 objid_t objid,
					 const krgnodemask_t *nodes,
					 int nr_nodes);

#endif /* STATIC_NODE_INFO_LINKER_H */
