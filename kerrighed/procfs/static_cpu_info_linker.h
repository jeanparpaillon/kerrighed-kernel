/** Static CPU information management.
 *  @file static_cpu_info_linker.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef STATIC_CPU_INFO_LINKER_H
#define STATIC_CPU_INFO_LINKER_H

#include <kerrighed/cpu_id.h>
#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include <asm/kerrighed/cpuinfo.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Static CPU informations */

typedef struct {
	cpuinfo_t info;
} krg_static_cpu_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct kddm_set *static_cpu_info_kddm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int static_cpu_info_init(void);
void init_static_cpu_info_objects(void);

/** Helper function to get static CPU informations.
 *  @author Renaud Lottiaux
 *
 *  @param node_id   Id of the node hosting the CPU we want informations on.
 *  @param cpu_id    Id of the CPU we want informations on.
 *
 *  @return  Structure containing information on the requested CPU.
 */
static inline krg_static_cpu_info_t *get_static_cpu_info(int node_id,
							 int cpu_id)
{
	return _fkddm_get_object(static_cpu_info_kddm_set,
				 __krg_cpu_id(node_id, cpu_id),
				 KDDM_NO_FREEZE|KDDM_NO_FT_REQ);
}

kerrighed_node_t cpu_info_default_owner(struct kddm_set *set,
					objid_t objid,
					const krgnodemask_t *nodes,
					int nr_nodes);

#endif /* STATIC_CPU_INFO LINKER_H */
