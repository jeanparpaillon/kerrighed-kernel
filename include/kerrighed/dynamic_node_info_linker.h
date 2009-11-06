/** Dynamic node informations management.
 *  @file dynamic_node_info_linker.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef DYNAMIC_NODE_INFO_LINKER_H
#define DYNAMIC_NODE_INFO_LINKER_H

#include <linux/hardirq.h>
#include <linux/procfs_internal.h>
#include <kerrighed/sys/types.h>
#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include <asm/kerrighed/meminfo.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Node related informations */

typedef struct {
	struct timespec idletime;
	struct timespec uptime;
	unsigned long avenrun[3];	/* Load averages */
	int last_pid;
	int nr_threads;
	unsigned long nr_running;
	unsigned long long nr_context_switches;
	unsigned long jif;
	unsigned long total_forks;
	unsigned long nr_iowait;
	u64 arch_irq;

	/* Dynamic memory informations */

	unsigned long totalram;
	unsigned long freeram;
	unsigned long bufferram;
	unsigned long totalhigh;
	unsigned long freehigh;
	unsigned long totalswap;
	unsigned long freeswap;

	unsigned long nr_pages[NR_LRU_LISTS - LRU_BASE];
	unsigned long nr_mlock;
	unsigned long nr_file_pages;
	unsigned long nr_file_dirty;
	unsigned long nr_writeback;
	unsigned long nr_anon_pages;
	unsigned long nr_file_mapped;
	unsigned long nr_page_table_pages;
	unsigned long nr_slab_reclaimable;
	unsigned long nr_slab_unreclaimable;
	unsigned long nr_unstable_nfs;
	unsigned long nr_bounce;
	unsigned long nr_writeback_temp;

	unsigned long quicklists;

	struct vmalloc_info vmi;
	unsigned long vmalloc_total;

	unsigned long allowed;
	unsigned long commited;

	unsigned long swapcache_pages;

	unsigned long nr_huge_pages;
	unsigned long free_huge_pages;
	unsigned long resv_huge_pages;
	unsigned long surplus_huge_pages;

	krg_arch_meminfo_t arch_meminfo;
} krg_dynamic_node_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct kddm_set *dynamic_node_info_kddm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int dynamic_node_info_init(void);
void init_dynamic_node_info_object(void);

/** Helper function to get dynamic node informations.
 *  @author Renaud Lottiaux
 *
 *  @param node_id   Id of the node we want informations on.
 *
 *  @return  Structure containing information on the requested node.
 */
static inline
krg_dynamic_node_info_t *get_dynamic_node_info(kerrighed_node_t nodeid)
{
	return _fkddm_get_object(dynamic_node_info_kddm_set, nodeid,
				 KDDM_NO_FREEZE|KDDM_NO_FT_REQ);
}

#endif /* DYNAMIC_NODE_INFO_LINKER_H */
