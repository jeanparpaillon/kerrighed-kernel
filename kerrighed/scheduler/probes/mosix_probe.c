/*
 *  kerrighed/scheduler/probes/mosix_probe.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *
 *  Based on Kerrighed/modules/scheduler_old/mosix_probe.c:
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Louis Rilling - Kerlabs
 */

/**
 *  Processor load computation.
 *  @file mosix_probe.c
 *
 *  Implementation of processor load computation functions.
 *  It is a simplified version of the MOSIX functions.
 *
 *  Original work by Amnon Shiloh and Amnon Barak.
 *
 *  @author Louis Rilling, Renaud Lottiaux, Marko Novak
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/rcupdate.h>
#include <linux/jiffies.h>
#include <kerrighed/pid.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/scheduler/info.h>
#include <kerrighed/scheduler/hooks.h>
#include <kerrighed/scheduler/probe.h>

#include "mosix_probe.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("CPU load probe based on MOSIX algorithms");

#undef DBG_MOSIX_PROBE

#ifdef DBG_MOSIX_PROBE
#define DEBUG(topic, level, format, args...) \
	printk(KERN_DEBUG "[%s]: " format, __PRETTY_FUNCTION__, ## args);
#else
#define DEBUG(topic, level, format, args...)
#endif

/* Compute processor load every second */
#define CF HZ

/* Speed of the standard processor */
/* #define STD_SPD 10000 */
/* Not used. Set this to 1 avoid long overflow in load compuation. */
#define STD_SPD 1

/* #define PROCESS_MEAN_LOAD_SCALE 4 */
#define PROCESS_MEAN_LOAD_SCALE 1

/* Values taken from MOSIX */
#define MEAN_LOAD_SCALE 128

#define MEAN_LOAD_DECAY 5
#define MEAN_LOAD_NEW_DATA 3

#define UPPER_LOAD_DECAY 7
#define UPPER_LOAD_NEW_DATA 1

#define CPU_USE_DECAY 3
#define CPU_USE_NEW_DATA 1

struct mosix_probe_info {
	struct krg_sched_module_info module_info;
	unsigned int load;    /**< Estimated load:
			       * approx. 4 * ticks used in CF ticks */
	unsigned int last_on; /**< load_ticks + 1 when last put on runqueue,
			       * 0 if not on runqueue */
	unsigned int ran;     /**< number of ticks used
			       * since last call to mp_calc_load */
};

static inline
struct mosix_probe_info *
to_mosix_probe_info(struct krg_sched_module_info *sched_info)
{
	return container_of(sched_info, struct mosix_probe_info, module_info);
}

struct mosix_probe_data mosix_data;
/* struct mosix_probe_data mosix_data_prev; */

/* Load informations readable from outside in the cluster */
unsigned long cpu_speed = 1;  /* Speed of each CPU */

unsigned long mean_load = 0; /* Value scaled by MEAN_LOAD_SCALE */
unsigned long upper_load = 0;

/* Load accumulators which are the basis to compute the machine load */
unsigned long load_adder;
unsigned int load_ticks = CF;

static struct scheduler_probe *mosix_probe;
enum mosix_probe_source_t {
	VALUE_MEAN_LOAD,
	VALUE_UPPER_LOAD,
	VALUE_NORM_MEAN_LOAD,
	VALUE_NORM_UPPER_LOAD,
	VALUE_SINGLE_PROCESS_LOAD,
	VALUE_NORM_SINGLE_PROCESS_LOAD,
	VALUE_PROCESS_LOAD,
	NR_VALUES,
};
static struct scheduler_probe_source *mosix_probe_sources[NR_VALUES + 1];


/* static u64 curr_jiffies; */
/* static u64 prev_jiffies; */

/**
 *  Function to initialize load informations of a process.
 *
 *  @param task		task on which info relates
 *  @param info		task info structure for mosix probe
 */
static void mosix_probe_init_info(struct task_struct *task,
				  struct mosix_probe_info *info)
{
	info->load = 0;
	if (task->state == TASK_RUNNING)
		info->last_on = load_ticks + 1;
	else
		info->last_on = 0;
	info->ran = 0;
}

static struct krg_sched_module_info *
mosix_probe_info_copy(struct task_struct *task,
		      struct krg_sched_module_info *info)
{
	struct mosix_probe_info *new_info;

	new_info = kmalloc(sizeof(*new_info), GFP_KERNEL);
	if (new_info) {
		mosix_probe_init_info(task, new_info);
		return &new_info->module_info;
	}
	return NULL;
}

static void mosix_probe_info_free(struct krg_sched_module_info *info)
{
	kfree(to_mosix_probe_info(info));
}

static int mosix_probe_info_export(struct epm_action *action,
				   struct ghost *ghost,
				   struct krg_sched_module_info *info)
{
	/* nothing to do */
	return 0;
}

static struct krg_sched_module_info *
mosix_probe_info_import(struct epm_action *action,
			struct ghost *ghost,
			struct task_struct *task)
{
	return mosix_probe_info_copy(task, NULL);
}

static struct krg_sched_module_info_type mosix_probe_module_info_type = {
	.name = "mosix probe",
	.owner = THIS_MODULE,
	.copy = mosix_probe_info_copy,
	.free = mosix_probe_info_free,
	.export = mosix_probe_info_export,
	.import = mosix_probe_info_import
};

/* Must be called under rcu_read_lock() */
static struct mosix_probe_info *get_mosix_probe_info(struct task_struct *task)
{
	struct krg_sched_module_info *mod_info;

	mod_info = krg_sched_module_info_get(task,
					     &mosix_probe_module_info_type);
	if (mod_info)
		return to_mosix_probe_info(mod_info);
	else
		return NULL;
}

static inline unsigned long new_mean_load(unsigned long old_load,
					  unsigned long new_load)
{
	return ((old_load * MEAN_LOAD_DECAY + new_load * MEAN_LOAD_NEW_DATA)
		/ (MEAN_LOAD_DECAY + MEAN_LOAD_NEW_DATA));
}

static inline unsigned long new_upper_load(unsigned long old_load,
					   unsigned long new_load)
{
	return ((old_load * UPPER_LOAD_DECAY + new_load * UPPER_LOAD_NEW_DATA)
		/ (UPPER_LOAD_DECAY + UPPER_LOAD_NEW_DATA));
}

static inline unsigned new_cpu_use(unsigned old_use,
				   unsigned new_use)
{
	return ((old_use * CPU_USE_DECAY + new_use * CPU_USE_NEW_DATA
		 + CPU_USE_DECAY + CPU_USE_NEW_DATA - 1)
		/ (CPU_USE_DECAY + CPU_USE_NEW_DATA));
}

/**
 *  Function to update the processor load generated by each process, according
 *  to their stats.
 *
 *  @param ticks   Number of clock ticks since the last update.
 */
static void update_processes_load(unsigned int ticks)
{
	struct task_struct *tsk;
	struct mosix_probe_info *p;

	rcu_read_lock();

	for_each_process(tsk) {
		if (unlikely(tsk->exit_state))
			continue;
		if (unlikely(!(task_pid_knr(tsk) & GLOBAL_PID_MASK)))
			continue;
		if (unlikely(!(p = get_mosix_probe_info(tsk))))
			continue;

		if (p->last_on) {
			p->ran += ticks + 1 - p->last_on;
			p->last_on = 1;
		}

		p->load = new_mean_load(p->load,
					(p->ran * PROCESS_MEAN_LOAD_SCALE * CF)
					/ ticks);
		p->ran = 0;
	}

	rcu_read_unlock();
}

/**
 *  Function to compute load stats of the last execution period of a process.
 *  We only monitor Kerrighed processes.
 *
 *  @param tsk   Process concerned.
 */
static void mp_process_off(struct task_struct *tsk)
{
	struct mosix_probe_info *p;

	rcu_read_lock();
	p = get_mosix_probe_info(tsk);
	if (p) {
		p->ran += load_ticks + 1 - p->last_on;
		p->last_on = 0;
	}
	rcu_read_unlock();
}

static void kmcb_process_off(unsigned long arg)
{
	mp_process_off((struct task_struct *) arg);
}

/**
 *  Function to initialize load stats of a process for a new execution period.
 *  We only monitor kerrighed processes.
 *
 *  @param tsk   Process concerned.
 */
static void mp_process_on(struct task_struct *tsk)
{
	struct mosix_probe_info *p;

	rcu_read_lock();
	p = get_mosix_probe_info(tsk);
	if (p)
		p->last_on = load_ticks + 1;
	rcu_read_unlock();
}

static void kmcb_process_on(unsigned long arg)
{
	mp_process_on((struct task_struct *) arg);
}

/**
 *  Function to update the processor load of the node.
 *  It is called approximatively every CF clock ticks. (CF being equal
 *  to HZ, called every second)
 */
static void mp_calc_load(void)
{
	unsigned long scaled_load;
	unsigned long load;
	unsigned int ticks;
/*	unsigned use; */

	load = load_adder;   /* Accumulated number of processes
			      * since last call */
	ticks = load_ticks;  /* Number of clock ticks since last call */
/*	use = cpu_use;       /\* Accumulated (ticks * num_cpu) efficiently used  */
/*				since last call -- not really computed *\/ */

	/* Reset the stats for the next period */
	load_adder = 0;
	load_ticks = 0;
/*	cpu_use = 0; */

	/* Make the load time-of-measure independent */
	load = (load * CF) / ticks;

	scaled_load = load * MEAN_LOAD_SCALE;

	if (scaled_load > mean_load)
		mean_load = new_mean_load(mean_load, scaled_load);
	else
		mean_load = scaled_load;

	if (load >= upper_load)
		upper_load = load;
	else
		upper_load = new_upper_load(upper_load, load);

	mosix_data.mosix_mean_load = (mean_load + MEAN_LOAD_SCALE / 2) / MEAN_LOAD_SCALE;
/*		+ mosix_single_process_load; */
	mosix_data.mosix_upper_load = upper_load;
/*		+ mosix_single_process_load; */

	mosix_data.mosix_norm_mean_load = (mosix_data.mosix_mean_load * STD_SPD) / cpu_speed;
	mosix_data.mosix_norm_upper_load = (mosix_data.mosix_upper_load * STD_SPD) / cpu_speed;

	update_processes_load(ticks);
}

/**
 *  Function to accumulate load stats at each clock tick.
 *  Called each time calc_load is called.
 *  This function is called in the timer interrupt,
 *  with the xtime_lock write lock held.
 *
 *  @param ticks   Clock ticks since last called.
 */
static void kmcb_accumulate_load(unsigned long ticks)
{
	unsigned long load;

	load_adder += nr_running();
/*	cpu_use += ticks * num_online_cpus(); */
	load_ticks += ticks;

	/* CF is equal to HZ, which means load is computed every second */
	if (load_ticks >= CF) {
		mp_calc_load();

		load = mosix_data.mosix_mean_load;

//    printk ("load %ld - mean_load %d - upper_load %ld - stable_export %ld\n",
//            load, mosix_mean_load, mosix_upper_load,
//            stable_export);

		DEBUG(DBG_MOSIX_PROBE, 4,
		      "computed_load : %ld (nr_running() is %lu)\n",
		      load,
		      nr_running());

		scheduler_probe_source_notify_update(
			mosix_probe_sources[VALUE_MEAN_LOAD]);
		scheduler_probe_source_notify_update(
			mosix_probe_sources[VALUE_UPPER_LOAD]);
		scheduler_probe_source_notify_update(
			mosix_probe_sources[VALUE_NORM_MEAN_LOAD]);
		scheduler_probe_source_notify_update(
			mosix_probe_sources[VALUE_NORM_UPPER_LOAD]);
/*		if (load >= ALARM_THRESHOLD) */
/*			send_alarm_to_analyzer(); */
	}
}

static void mosix_probe_init_variables(void)
{
	load_adder = CF * (nr_running() - 1);
/*	accurate_use = CF * num_online_cpus(); */
/*	cpu_use = CF * num_online_cpus(); */
/*	mosix_data.mosix_single_process_load = CF / num_online_cpus(); */
	mosix_data.mosix_single_process_load = CF;
	mosix_data.mosix_norm_single_process_load =
		mosix_data.mosix_single_process_load * STD_SPD / cpu_speed;

/*         |+ called each time calc_load is called +| */
/*         hook_register(&kh_calc_load, kcb_accumulate_load); */
/*         |+ called when a process is added to the run queue +| */
/*         hook_register(&kh_process_on, kcb_process_on); */
/*         |+ called when a process is removed from the run queue +| */
/*         hook_register(&kh_process_off, kcb_process_off); */
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET(value_mean_load, unsigned long, value_p, nr)
{
	*value_p = mosix_data.mosix_mean_load;
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_mean_load, page)
{
	return sprintf(page, "%lu\n", mosix_data.mosix_mean_load);
}

/* DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_mean_load) */
/* { */
/*	int isChanged = 0; */
/*	if (mosix_data.mosix_mean_load != mosix_data_prev.mosix_mean_load) { */
/*		isChanged = 1; */
/*		mosix_data_prev.mosix_mean_load = mosix_data.mosix_mean_load; */
/*	} */

/*	return isChanged; */
/* } */

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_mean_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_mean_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_mean_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_mean_load, unsigned long),
/*	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_mean_load), */
END_SCHEDULER_PROBE_SOURCE_TYPE(value_mean_load);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(value_upper_load, unsigned long, value_p, nr)
{
	*value_p = upper_load;
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_upper_load, page)
{
        return sprintf(page, "%lu\n", mosix_data.mosix_upper_load);
}

/* DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_upper_load) */
/* { */
/*         int isChanged = 0; */
/*         if (mosix_data.mosix_upper_load != mosix_data_prev.mosix_upper_load) { */
/*                 isChanged = 1; */
/*                 mosix_data_prev.mosix_upper_load = mosix_data.mosix_upper_load; */
/*         } */

/*         return isChanged; */

/* } */

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_upper_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_upper_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_upper_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_upper_load, unsigned long),
/*	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_upper_load), */
END_SCHEDULER_PROBE_SOURCE_TYPE(value_upper_load);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(value_single_process_load,
				  unsigned long, value_p, nr)
{
	*value_p = mosix_data.mosix_single_process_load;
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_single_process_load, page)
{
        return sprintf(page, "%lu\n", mosix_data.mosix_single_process_load);
}

/* DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_single_process_load) */
/* { */
/*         int isChanged = 0; */
/*         if (mosix_data.mosix_single_process_load !=  */
/*		mosix_data_prev.mosix_single_process_load) { */

/*                 isChanged = 1; */
/*                 mosix_data_prev.mosix_single_process_load =  */
/*			mosix_data.mosix_single_process_load; */
/*         } */

/*         return isChanged; */

/* } */

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_single_process_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_single_process_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_single_process_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_single_process_load,
					   unsigned long),
/*	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_single_process_load), */
END_SCHEDULER_PROBE_SOURCE_TYPE(value_single_process_load);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(value_norm_mean_load,
				  unsigned long, value_p, nr)
{
	*value_p = mosix_data.mosix_norm_mean_load;
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_norm_mean_load, page)
{
        return sprintf(page, "%lu\n", mosix_data.mosix_norm_mean_load);
}

/* DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_norm_mean_load) */
/* { */
/*         int isChanged = 0; */
/*         if (mosix_data.mosix_norm_mean_load !=  */
/*		mosix_data_prev.mosix_norm_mean_load) { */

/*                 isChanged = 1; */
/*                 mosix_data_prev.mosix_norm_mean_load =  */
/*			mosix_data.mosix_norm_mean_load; */
/*         } */

/*         return isChanged; */
/* } */

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_norm_mean_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_norm_mean_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_norm_mean_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_norm_mean_load, unsigned long),
/*	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_norm_mean_load), */
END_SCHEDULER_PROBE_SOURCE_TYPE(value_norm_mean_load);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(value_norm_upper_load,
				  unsigned long, value_p, nr)
{
	*value_p = mosix_data.mosix_norm_upper_load;
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_norm_upper_load, page)
{
        return sprintf(page, "%lu\n", mosix_data.mosix_norm_upper_load);
}

/* DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_norm_upper_load) */
/* { */
/*         int isChanged = 0; */
/*         if (mosix_data.mosix_norm_upper_load != */
/*                 mosix_data_prev.mosix_norm_upper_load) { */

/*                 isChanged = 1; */
/*                 mosix_data_prev.mosix_norm_upper_load = */
/*                         mosix_data.mosix_norm_upper_load; */
/*         } */

/*         return isChanged; */
/* } */

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_norm_upper_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_norm_upper_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_norm_upper_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_norm_upper_load,
					   unsigned long),
/*	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_norm_upper_load), */
END_SCHEDULER_PROBE_SOURCE_TYPE(value_norm_upper_load);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(value_norm_single_process_load,
		       unsigned long, value_p, nr)
{
	*value_p = mosix_data.mosix_norm_single_process_load;
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_norm_single_process_load, page)
{
        return sprintf(page, "%lu\n",
		       mosix_data.mosix_norm_single_process_load);
}

/* DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_norm_single_process_load) */
/* { */
/*         int isChanged = 0; */
/*         if (mosix_data.mosix_norm_single_process_load != */
/*                 mosix_data_prev.mosix_norm_single_process_load) { */

/*                 isChanged = 1; */
/*                 mosix_data_prev.mosix_norm_single_process_load = */
/*                         mosix_data.mosix_norm_single_process_load; */
/*         } */

/*         return isChanged; */
/* } */

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_norm_single_process_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_norm_single_process_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_norm_single_process_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_norm_single_process_load,
					   unsigned long),
/*	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(value_norm_single_process_load), */
END_SCHEDULER_PROBE_SOURCE_TYPE(value_norm_single_process_load);

DEFINE_SCHEDULER_PROBE_SOURCE_GET_WITH_INPUT(value_process_load,
					     unsigned long, value_p, nr,
					     pid_t, in_value_p, in_nr)
{
	pid_t pid;
	struct task_struct *task;
	struct mosix_probe_info *info = NULL;
	int i;

	rcu_read_lock();
	for (i = 0; i < in_nr && i < nr; i++) {
		pid = in_value_p[i];

		task = find_task_by_kpid(pid);
		if (!task)
			break;
		info = get_mosix_probe_info(task);
		if (!info)
			break;

		value_p[i] = info->load;
	}
	rcu_read_unlock();

	return i;
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_process_load),
	.SCHEDULER_PROBE_SOURCE_GET(value_process_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_process_load, unsigned long),
	.SCHEDULER_PROBE_SOURCE_PARAM_TYPE(value_process_load, pid_t),
END_SCHEDULER_PROBE_SOURCE_TYPE(value_process_load);

/* static void measure_mosix(void) */
/* { */
/*	curr_jiffies = get_jiffies_64(); */
/*	load_adder += nr_running(); */
/*	load_ticks += (curr_jiffies - prev_jiffies); */
/*	mp_calc_load(); */
/*	prev_jiffies = curr_jiffies; */
/* } */

static SCHEDULER_PROBE_TYPE(mosix_probe_type, NULL, NULL /* measure_mosix */);

static int mod_info_not_registered;
static int probe_not_registered;

int mosix_probe_init(void)
{
	int err = -ENOMEM;
	char *err_msg = NULL;
	int i;

	mosix_probe_init_variables();

	mosix_probe_sources[VALUE_MEAN_LOAD] =
		scheduler_probe_source_create(&value_mean_load_type,
					      "mean_load");
        mosix_probe_sources[VALUE_UPPER_LOAD] =
		scheduler_probe_source_create(&value_upper_load_type,
					      "upper_load");
        mosix_probe_sources[VALUE_SINGLE_PROCESS_LOAD] =
		scheduler_probe_source_create(&value_single_process_load_type,
					      "single_process_load");
        mosix_probe_sources[VALUE_NORM_MEAN_LOAD] =
		scheduler_probe_source_create(&value_norm_mean_load_type,
					      "norm_mean_load");
        mosix_probe_sources[VALUE_NORM_UPPER_LOAD] =
		scheduler_probe_source_create(&value_norm_upper_load_type,
					      "norm_upper_load");
        mosix_probe_sources[VALUE_NORM_SINGLE_PROCESS_LOAD] =
		scheduler_probe_source_create(
			&value_norm_single_process_load_type,
			"norm_single_process_load");
        mosix_probe_sources[VALUE_PROCESS_LOAD] =
		scheduler_probe_source_create(&value_process_load_type,
					      "process_load");
	mosix_probe_sources[NR_VALUES] = NULL;

	for (i=0; i<NR_VALUES; i++) {
		if (mosix_probe_sources[i] == NULL) {
			printk(KERN_ERR "error: cannot initialize mosix probe "
			       "values\n");
			goto out_kmalloc;
		}
	}

	mosix_probe = scheduler_probe_create(&mosix_probe_type,
					     MOSIX_PROBE_NAME,
					     mosix_probe_sources,
					     NULL);
	if (mosix_probe == NULL) {
		printk(KERN_ERR "error: mosix_probe creation failed\n");
		goto out_kmalloc;
	}

/*         |+ perform first measurement +| */
/*         measure_mosix(); */
/*         mosix_data_prev = mosix_data; */

/*	curr_jiffies = get_jiffies_64(); */
/*	prev_jiffies = get_jiffies_64(); */

	/*
	 * We cannot call unregister in init, so the system may have to live
	 * with partial hook init until module is unloaded.
	 */
	err = module_hook_register(&kmh_process_on, kmcb_process_on,
				   THIS_MODULE);
	if (err)
		goto err_hooks;
	err = module_hook_register(&kmh_process_off, kmcb_process_off,
				   THIS_MODULE);
	if (err)
		goto err_other_hooks;
	err = module_hook_register(&kmh_calc_load, kmcb_accumulate_load,
				   THIS_MODULE);
	if (err)
		goto err_other_hooks;

	err = krg_sched_module_info_register(&mosix_probe_module_info_type);
	if (err)
		goto err_mod_info;

	err = scheduler_probe_register(mosix_probe);
	if (err)
		goto err_register;

out:
	return err;

err_hooks:
	scheduler_probe_free(mosix_probe);
out_kmalloc:
	for (i=0; i<NR_VALUES; i++)
		if (mosix_probe_sources[i])
			scheduler_probe_source_free(mosix_probe_sources[i]);
	goto out;

err_other_hooks:
	if (!err_msg)
		err_msg = "inconsistent hooks initialization";
err_mod_info:
	mod_info_not_registered = 1;
	if (!err_msg)
		err_msg = "could not finish module initialization";
err_register:
	probe_not_registered = 1;
	if (!err_msg)
		err_msg = "could not register probe";

	printk(KERN_ERR "[%s] error %d: %s!\n"
	       "Module cannot cleanly self-unload.\n"
	       "Please unload the module.\n",
	       __PRETTY_FUNCTION__, err, err_msg);
	err = 0;
	goto out;
}

void mosix_probe_exit(void)
{
	int i=0;

	if (!probe_not_registered)
		scheduler_probe_unregister(mosix_probe);

	if (!mod_info_not_registered)
		krg_sched_module_info_unregister(&mosix_probe_module_info_type);

	module_hook_unregister(&kmh_calc_load, kmcb_accumulate_load);
	module_hook_unregister(&kmh_process_off, kmcb_process_off);
	module_hook_unregister(&kmh_process_on, kmcb_process_on);

	scheduler_probe_free(mosix_probe);
	while (mosix_probe_sources[i] != NULL) {
		scheduler_probe_source_free(mosix_probe_sources[i]);
		i++;
	}
}

module_init(mosix_probe_init);
module_exit(mosix_probe_exit);
