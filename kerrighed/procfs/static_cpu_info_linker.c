/** Static CPU information management.
 *  @file static_cpu_info_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <kerrighed/cpu_id.h>
#include <asm/kerrighed/cpuinfo.h>
#include <asm/processor.h>
#include <linux/swap.h>

#include <kddm/kddm.h>

#include "static_cpu_info_linker.h"

#include <kerrighed/debug.h>

struct kddm_set *static_cpu_info_kddm_set;

/*****************************************************************************/
/*                                                                           */
/*                    STATIC CPU INFO KDDM IO FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

kerrighed_node_t cpu_info_default_owner(struct kddm_set *set,
					objid_t objid,
					const krgnodemask_t *nodes,
					int nr_nodes)
{
	return krg_cpu_node(objid);
}

/****************************************************************************/

/* Init the cpu info IO linker */

static struct iolinker_struct static_cpu_info_io_linker = {
	.linker_name = "stat_cpu_info",
	.linker_id = STATIC_CPU_INFO_LINKER,
	.default_owner = cpu_info_default_owner
};

void init_static_cpu_info_objects(void)
{
	krg_static_cpu_info_t *static_cpu_info;
	int cpu_id, i;

	for_each_online_cpu (i) {
		cpu_id = krg_cpu_id(i);
		cpu_data(i).krg_cpu_id = cpu_id;

		static_cpu_info =
			_kddm_grab_object(static_cpu_info_kddm_set, cpu_id);

		static_cpu_info->info = cpu_data(i);
#ifndef CONFIG_USERMODE
		static_cpu_info->info.cpu_khz = cpu_khz;
#endif

		_kddm_put_object(static_cpu_info_kddm_set, cpu_id);
	}
}

int static_cpu_info_init(void)
{
	register_io_linker(STATIC_CPU_INFO_LINKER, &static_cpu_info_io_linker);

	/* Create the CPU info kddm set */

	static_cpu_info_kddm_set =
		create_new_kddm_set(kddm_def_ns,
				    STATIC_CPU_INFO_KDDM_ID,
				    STATIC_CPU_INFO_LINKER,
				    KDDM_CUSTOM_DEF_OWNER,
				    sizeof(krg_static_cpu_info_t),
				    0);
	if (IS_ERR(static_cpu_info_kddm_set))
		OOM;

	init_static_cpu_info_objects();

	return 0;
}
