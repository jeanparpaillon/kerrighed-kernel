/** Static node information management.
 *  @file static_node_info_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#define MODULE_NAME "Static Node Info"
#include "debug_procfs.h"

#ifndef FILE_NONE
#  if defined(FILE_STATIC_NODE_INFO) || defined(FILE_ALL)
#     define DEBUG_THIS_MODULE
#  endif
#endif

#include <kerrighed/debug.h>

#include <linux/swap.h>
#include <kddm/kddm.h>

#include "static_node_info_linker.h"

struct kddm_set *static_node_info_kddm_set;

/*****************************************************************************/
/*                                                                           */
/*                     STATIC NODE INFO KDDM IO FUNCTIONS                    */
/*                                                                           */
/*****************************************************************************/

kerrighed_node_t node_info_default_owner(struct kddm_set *set,
					 objid_t objid,
					 const krgnodemask_t *nodes,
					 int nr_nodes)
{
	return objid;
}

/****************************************************************************/

/* Init the static node info IO linker */

static struct iolinker_struct static_node_info_io_linker = {
	.default_owner = node_info_default_owner,
	.linker_name = "stat_node_nfo",
	.linker_id = STATIC_NODE_INFO_LINKER,
};

int static_node_info_init()
{
	krg_static_node_info_t *static_node_info;

	register_io_linker(STATIC_NODE_INFO_LINKER,
			   &static_node_info_io_linker);

	/* Create the static node info kddm set */

	static_node_info_kddm_set =
		create_new_kddm_set(kddm_def_ns,
				    STATIC_NODE_INFO_KDDM_ID,
				    STATIC_NODE_INFO_LINKER,
				    KDDM_CUSTOM_DEF_OWNER,
				    sizeof(krg_static_node_info_t),
				    0);
	if (IS_ERR(static_node_info_kddm_set))
		OOM;

	static_node_info = _kddm_grab_object(static_node_info_kddm_set,
					     kerrighed_node_id);

	static_node_info->nr_cpu = num_online_cpus();
	static_node_info->totalram = totalram_pages;
	static_node_info->totalhigh = totalhigh_pages;

	_kddm_put_object(static_node_info_kddm_set, kerrighed_node_id);

	return 0;
}
