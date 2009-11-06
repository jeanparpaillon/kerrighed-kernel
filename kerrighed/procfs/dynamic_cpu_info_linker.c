/** Dynamic CPU information management.
 *  @file dynamic_cpu_info_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/swap.h>
#include <linux/kernel_stat.h>
#include <linux/hardirq.h>

#include <kerrighed/cpu_id.h>
#include <kerrighed/workqueue.h>
#include <kddm/kddm.h>

#include <asm/cputime.h>

#include "dynamic_cpu_info_linker.h"
#include "static_cpu_info_linker.h"

#include <kerrighed/debug.h>

struct kddm_set *dynamic_cpu_info_kddm_set;

/*****************************************************************************/
/*                                                                           */
/*                   DYNAMIC CPU INFO KDDM IO FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

/****************************************************************************/

/* Init the dynamic cpu info IO linker */

static struct iolinker_struct dynamic_cpu_info_io_linker = {
	.default_owner = cpu_info_default_owner,
	.linker_name = "dyn_cpu_nfo",
	.linker_id = DYNAMIC_CPU_INFO_LINKER,
};

static void update_dynamic_cpu_info_worker(struct work_struct *data);
static DECLARE_DELAYED_WORK(update_dynamic_cpu_info_work,
			    update_dynamic_cpu_info_worker);

/** Update dynamic CPU informations for all local CPU.
 *  @author Renaud Lottiaux
 */
static void update_dynamic_cpu_info_worker(struct work_struct *data)
{
	krg_dynamic_cpu_info_t *dynamic_cpu_info;
	int i, j, cpu_id;

	for_each_online_cpu(i) {
		cpu_id = krg_cpu_id(i);
		dynamic_cpu_info =
			_kddm_grab_object(dynamic_cpu_info_kddm_set, cpu_id);

		/* Compute data for stat proc file */

		dynamic_cpu_info->stat = kstat_cpu(i);
#ifdef arch_idle_time
		dynamic_cpu_info->stat.cpustat.idle =
			cputime64_add(dynamic_cpu_info->stat.cpustat.idle,
				      arch_idle_time(i));
#endif
		dynamic_cpu_info->total_intr = 0;
		for (j = 0; j < NR_IRQS; j++) {
			unsigned int *irqs =
				krg_dynamic_cpu_info_irqs(dynamic_cpu_info);
#ifdef CONFIG_GENERIC_HARDIRQS
			irqs[j] = kstat_irqs_cpu(j, i);
#endif
			dynamic_cpu_info->total_intr += irqs[j];
		}
#ifdef arch_irq_stat_cpu
		dynamic_cpu_info->total_intr += arch_irq_stat_cpu(i);
#endif

		_kddm_put_object(dynamic_cpu_info_kddm_set, cpu_id);
	}

	queue_delayed_work(krg_wq, &update_dynamic_cpu_info_work, HZ);
}

void init_dynamic_cpu_info_objects(void)
{
	update_dynamic_cpu_info_worker(&update_dynamic_cpu_info_work.work);
}

int dynamic_cpu_info_init(void)
{
	register_io_linker(DYNAMIC_CPU_INFO_LINKER,
			   &dynamic_cpu_info_io_linker);

	/* Create the CPU info container */

	dynamic_cpu_info_kddm_set =
		create_new_kddm_set(kddm_def_ns,
				    DYNAMIC_CPU_INFO_KDDM_ID,
				    DYNAMIC_CPU_INFO_LINKER,
				    KDDM_CUSTOM_DEF_OWNER,
				    sizeof(krg_dynamic_cpu_info_t),
				    0);
	if (IS_ERR(dynamic_cpu_info_kddm_set))
		OOM;

	init_dynamic_cpu_info_objects();
	return 0;
}
