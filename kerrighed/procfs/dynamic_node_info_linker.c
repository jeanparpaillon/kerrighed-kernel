/** Dynamic node information management.
 *  @file dynamic_node_info_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/swap.h>
#include <linux/kernel_stat.h>
#include <linux/pagemap.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/vmstat.h>
#include <linux/quicklist.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/workqueue.h>

#include <kerrighed/workqueue.h>
#include <kddm/kddm.h>

#include <kerrighed/dynamic_node_info_linker.h>
#include "static_node_info_linker.h"

#include <kerrighed/debug.h>

/* Kddm set of node information locations */
struct kddm_set *dynamic_node_info_kddm_set;

/*****************************************************************************/
/*                                                                           */
/*                    DYNAMIC NODE INFO KDDM IO FUNCTIONS                    */
/*                                                                           */
/*****************************************************************************/

/****************************************************************************/

/* Init the dynamic node info IO linker */

static struct iolinker_struct dynamic_node_info_io_linker = {
	.default_owner = node_info_default_owner,
	.linker_name = "dyn_node_nfo",
	.linker_id = DYNAMIC_NODE_INFO_LINKER,
};

static void update_dynamic_node_info_worker(struct work_struct *work);
static DECLARE_DELAYED_WORK(update_dynamic_node_info_work,
			    update_dynamic_node_info_worker);

void
__attribute__((weak))
krg_arch_fill_dynamic_node_info(krg_dynamic_node_info_t *info)
{
}

/** Update the dynamic informations for the local node.
 *  @author Renaud Lottiaux
 */
static void update_dynamic_node_info_worker(struct work_struct *work)
{
	krg_dynamic_node_info_t *dynamic_node_info;
	cputime_t idletime = cputime_add(init_task.utime, init_task.stime);
	struct sysinfo sysinfo;
	struct timespec boottime;
	unsigned long jif, seq;
	int i;

	dynamic_node_info = _kddm_grab_object(dynamic_node_info_kddm_set,
					      kerrighed_node_id);

	/* Compute data for uptime proc file */

	cputime_to_timespec(idletime, &dynamic_node_info->idletime);
	do_posix_clock_monotonic_gettime(&dynamic_node_info->uptime);
	monotonic_to_bootbased(&dynamic_node_info->uptime);

	/* Compute data for loadavg proc file */

	do {
		seq = read_seqbegin(&xtime_lock);
		dynamic_node_info->avenrun[0] = avenrun[0];
		dynamic_node_info->avenrun[1] = avenrun[1];
		dynamic_node_info->avenrun[2] = avenrun[2];
	} while (read_seqretry(&xtime_lock, seq));
	dynamic_node_info->last_pid = task_active_pid_ns(current)->last_pid;
	dynamic_node_info->nr_threads = nr_threads;
	dynamic_node_info->nr_running = nr_running();

	getboottime(&boottime);
	jif = boottime.tv_sec;

	dynamic_node_info->jif = (unsigned long)jif;
	dynamic_node_info->total_forks = total_forks;
	dynamic_node_info->nr_iowait = nr_iowait();
	dynamic_node_info->nr_context_switches = nr_context_switches();

#ifdef arch_irq_stat
	dynamic_node_info->arch_irq = arch_irq_stat();
#else
	dynamic_node_info->arch_irq = 0;
#endif

	/* Compute data for meminfo proc file */

	si_meminfo(&sysinfo);
	si_swapinfo(&sysinfo);

	dynamic_node_info->totalram = sysinfo.totalram;
	dynamic_node_info->freeram = sysinfo.freeram;
	dynamic_node_info->bufferram = sysinfo.bufferram;
	dynamic_node_info->totalhigh = sysinfo.totalhigh;
	dynamic_node_info->freehigh = sysinfo.freehigh;
	dynamic_node_info->totalswap = sysinfo.totalswap;
	dynamic_node_info->freeswap = sysinfo.freeswap;
	dynamic_node_info->totalram = sysinfo.totalram;
	dynamic_node_info->swapcache_pages = total_swapcache_pages;

	for_each_lru(i)
		dynamic_node_info->nr_pages[i - LRU_BASE] = global_page_state(i);
#ifdef CONFIG_UNEVICTABLE_LRU
	dynamic_node_info->nr_mlock = global_page_state(NR_MLOCK);
#else
	dynamic_node_info->nr_mlock = 0;
#endif
	dynamic_node_info->nr_file_pages = global_page_state(NR_FILE_PAGES);
	dynamic_node_info->nr_file_dirty = global_page_state(NR_FILE_DIRTY);
	dynamic_node_info->nr_writeback = global_page_state(NR_WRITEBACK);
	dynamic_node_info->nr_anon_pages = global_page_state(NR_ANON_PAGES);
	dynamic_node_info->nr_file_mapped = global_page_state(NR_FILE_MAPPED);
	dynamic_node_info->nr_bounce = global_page_state(NR_BOUNCE);
	dynamic_node_info->nr_page_table_pages =
		global_page_state(NR_PAGETABLE);
	dynamic_node_info->nr_slab_reclaimable =
		global_page_state(NR_SLAB_RECLAIMABLE);
	dynamic_node_info->nr_slab_unreclaimable =
		global_page_state(NR_SLAB_UNRECLAIMABLE);
	dynamic_node_info->nr_unstable_nfs =
		global_page_state(NR_UNSTABLE_NFS);
	dynamic_node_info->nr_writeback_temp =
		global_page_state(NR_WRITEBACK_TEMP);

	dynamic_node_info->quicklists = quicklist_total_size();

	dynamic_node_info->allowed = ((totalram_pages - hugetlb_total_pages())
				      * sysctl_overcommit_ratio / 100) +
		                     total_swap_pages;

	dynamic_node_info->commited = percpu_counter_read_positive(&vm_committed_as);

	get_vmalloc_info(&dynamic_node_info->vmi);
	dynamic_node_info->vmalloc_total = VMALLOC_TOTAL;

#ifdef CONFIG_HUGETLB_PAGE
	dynamic_node_info->nr_huge_pages = default_hstate.nr_huge_pages;
	dynamic_node_info->free_huge_pages = default_hstate.free_huge_pages;
	dynamic_node_info->resv_huge_pages = default_hstate.resv_huge_pages;
	dynamic_node_info->surplus_huge_pages =
		default_hstate.surplus_huge_pages;
#else
	dynamic_node_info->nr_huge_pages = 0;
	dynamic_node_info->free_huge_pages = 0;
	dynamic_node_info->resv_huge_pages = 0;
	dynamic_node_info->surplus_huge_pages = 0;
#endif

	krg_arch_fill_dynamic_node_info(dynamic_node_info);

	_kddm_put_object(dynamic_node_info_kddm_set, kerrighed_node_id);

	queue_delayed_work(krg_wq, &update_dynamic_node_info_work, HZ);
}

int dynamic_node_info_init(void)
{
	register_io_linker(DYNAMIC_NODE_INFO_LINKER,
			   &dynamic_node_info_io_linker);

	/* Create the node info kddm set */

	dynamic_node_info_kddm_set =
		create_new_kddm_set(kddm_def_ns, DYNAMIC_NODE_INFO_KDDM_ID,
				    DYNAMIC_NODE_INFO_LINKER,
				    KDDM_CUSTOM_DEF_OWNER,
				    sizeof(krg_dynamic_node_info_t), 0);
	if (IS_ERR(dynamic_node_info_kddm_set))
		OOM;

	/* Start periodic updates */
	queue_delayed_work(krg_wq, &update_dynamic_node_info_work, 0);

	return 0;
}
