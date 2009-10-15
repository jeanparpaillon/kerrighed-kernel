/** Dynamic per CPU informations management.
 *  @file dynamic_cpu_info_linker.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef DYNAMIC_CPU_INFO_LINKER_H
#define DYNAMIC_CPU_INFO_LINKER_H

#include <linux/irqnr.h>
#include <linux/kernel_stat.h>
#include <kerrighed/cpu_id.h>
#include <kddm/kddm.h>
#include <kddm/object_server.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Dynamic CPU informations */

typedef struct {
	struct kernel_stat stat;
#ifdef CONFIG_GENERIC_HARDIRQS
	unsigned int irqs[NR_IRQS];
#endif
	u64 total_intr;
} krg_dynamic_cpu_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct kddm_set *dynamic_cpu_info_kddm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int dynamic_cpu_info_init(void);

/** Helper function to get dynamic CPU info
 *  @author Renaud Lottiaux
 *
 *  @param node_id   Id of the node hosting the CPU we want informations on.
 *  @param cpu_id    Id of the CPU we want informations on.
 *
 *  @return  Structure containing information on the requested CPU.
 */
static inline krg_dynamic_cpu_info_t *get_dynamic_cpu_info(int node_id,
							   int cpu_id)
{
	return _fkddm_get_object(dynamic_cpu_info_kddm_set,
				 __krg_cpu_id(node_id, cpu_id),
				 KDDM_NO_FREEZE|KDDM_NO_FT_REQ);
}

static inline
unsigned int *krg_dynamic_cpu_info_irqs(krg_dynamic_cpu_info_t *info)
{
#ifdef CONFIG_GENERIC_HARDIRQS
	return &info->irqs[0];
#else
	return &info->stat.irqs[0];
#endif
}

#endif /* DYNAMIC_CPU_INFO LINKER_H */
