/*
 *  kerrighed/scheduler/probes/cpu_probe.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <kerrighed/scheduler/probe.h>
#include <asm/cputime.h>

#include "cpu_probe.h"

static cpu_probe_data_t *probe_data;
static cpu_probe_data_t *probe_data_prev;

static clock_t *cpu_used;
static clock_t *cpu_total;
static clock_t *cpu_used_prev;
static clock_t *cpu_total_prev;

MODULE_LICENSE("LGPL");
MODULE_AUTHOR("Marko Novak <marko.novak@xlab.si>, "
	      "Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("CPU load probe module.");


static struct scheduler_probe *cpu_probe;
static int active;

#undef DEBUG_MONITOR

#ifdef DEBUG_MONITOR
#define PDEBUG(format, args...) printk(format, ## args)
#else
#define PDEBUG(format, args...)
#endif

/* calcilates CPU usage of i-th CPU (in percent). */
static inline unsigned long calc_cpu_used(int i)
{
	PDEBUG(KERN_INFO "cpu_measurement %lu %lu\n", probe_data[i].cpu_used,
		probe_data[i].cpu_total);
	return probe_data[i].cpu_used*100 / probe_data[i].cpu_total;
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET_WITH_INPUT(cpu_probe_load,
					     unsigned long, load_p, nr,
					     int, idx_p, in_nr)
{
	int i;

	if (in_nr)
		/* Only show the cpus queried */
		for (i = 0; i < in_nr && i < nr; i++) {
			if (idx_p[i] < num_online_cpus())
				*load_p++ = calc_cpu_used(idx_p[i]);
			else
				return -EINVAL;
		}
	else
		/* Show as many CPUs as possible */
		for (i = 0; i < nr && i < num_online_cpus(); i++)
			*load_p++ = calc_cpu_used(i);
	return i;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(cpu_probe_load, page)
{
	size_t size = SCHEDULER_PROBE_SOURCE_ATTR_SIZE;
	ssize_t count;
	int tmp_count;
	int i;

	PDEBUG(KERN_INFO "cpu_probe_source_show function called!\n");

	tmp_count = snprintf(page, size, "%lu\n", calc_cpu_used(0));
	count = tmp_count;
	for(i = 1;
	    tmp_count >= 0 && count + 1 < size && i < num_online_cpus();
	    i++) {
		tmp_count = snprintf(page + count, size - count,
				     "%lu\n", calc_cpu_used(i));
		if (tmp_count >= 0)
			count += tmp_count;
	}

	return (tmp_count < 0) ? tmp_count : min((size_t) count + 1, size);
}

static void measure_cpu(void)
{
	int i;

	PDEBUG("cpu_probe: start.\n");

	for(i=0; i<num_online_cpus(); i++) {
		cpu_used[i] =
			cputime64_to_clock_t(kstat_cpu(i).cpustat.user) +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.nice) +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.system) +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.iowait) +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.irq) +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.softirq) +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.steal);
		cpu_total[i] = cpu_used[i] +
			cputime64_to_clock_t(kstat_cpu(i).cpustat.idle);

		//spin_lock( &(probe_data[i].lock) );
		probe_data[i].cpu_used = cpu_used[i] - cpu_used_prev[i];
		probe_data[i].cpu_total = cpu_total[i] - cpu_total_prev[i];
		//spin_unlock( &(probe_data[i].lock) );

		PDEBUG("measurements for CPU%d: used=%llu total=%llu\n",
			i, (unsigned long long)cpu_used[i],
			(unsigned long long)cpu_total[i]);

		cpu_used_prev[i] = cpu_used[i];
		cpu_total_prev[i] = cpu_total[i];
	}

	PDEBUG("cpu_probe: done\n.");
}

DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(cpu_probe_load)
{
	int i;
	int isChanged = 0;

	if (!active)
		return 0;

	for (i=0; i<num_online_cpus(); i++) {
		if (probe_data[i].cpu_used!=probe_data_prev[i].cpu_used ||
			probe_data[i].cpu_total!=probe_data_prev[i].cpu_total) {

			isChanged = 1;
			break;
		}
	}

	if (isChanged) {
		for (i=0; i<num_online_cpus(); i++) {
			probe_data_prev[i] = probe_data[i];
		}
	}

	return isChanged;
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(cpu_probe_load),
	.SCHEDULER_PROBE_SOURCE_GET(cpu_probe_load),
	.SCHEDULER_PROBE_SOURCE_SHOW(cpu_probe_load),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(cpu_probe_load, unsigned long),
	.SCHEDULER_PROBE_SOURCE_PARAM_TYPE(cpu_probe_load, int),
	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(cpu_probe_load),
END_SCHEDULER_PROBE_SOURCE_TYPE(cpu_probe_load);

static struct scheduler_probe_source *cpu_probe_sources[2];

static ssize_t active_attr_show(struct scheduler_probe *probe, char *page)
{
	return sprintf(page, "%d", active);
}

static ssize_t active_attr_store(struct scheduler_probe *probe,
				 const char *page, size_t count)
{
	int new_active;
	char *last_read;

	new_active = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	active = !!new_active;
	return count;
}

static SCHEDULER_PROBE_ATTRIBUTE(active_attr, "active", 0644,
				 active_attr_show, active_attr_store);

static struct scheduler_probe_attribute *cpu_probe_attrs[] = {
	&active_attr,
	NULL
};

static SCHEDULER_PROBE_TYPE(cpu_probe_type, cpu_probe_attrs, measure_cpu);

int init_module()
{
	int i;
	int err = -ENOMEM;

	probe_data = (cpu_probe_data_t *)kmalloc(sizeof(cpu_probe_data_t)*num_online_cpus(), GFP_KERNEL);
	probe_data_prev = (cpu_probe_data_t *)kmalloc(sizeof(cpu_probe_data_t)*num_online_cpus(), GFP_KERNEL);
	cpu_used = (clock_t *)kmalloc(sizeof(clock_t)*num_online_cpus(), GFP_KERNEL);
	cpu_total = (clock_t *)kmalloc(sizeof(clock_t)*num_online_cpus(), GFP_KERNEL);
	cpu_used_prev = (clock_t *)kmalloc(sizeof(clock_t)*num_online_cpus(), GFP_KERNEL);
	cpu_total_prev = (clock_t *)kmalloc(sizeof(clock_t)*num_online_cpus(), GFP_KERNEL);

	if (probe_data == NULL || probe_data_prev==NULL || cpu_used==NULL ||
	    cpu_total==NULL || cpu_used_prev==NULL || cpu_total_prev==NULL) {
		printk(KERN_ALERT "cpu_probe initialization failed: cannot"
		       " allocate memory for internal structures!\n");
		goto out_kmalloc;
	}

        cpu_probe_sources[0] = scheduler_probe_source_create(
		&cpu_probe_load_type,
		"cpu_usage");
	cpu_probe_sources[1] = NULL;

	if (cpu_probe_sources[0] == NULL) {
		printk(KERN_ERR "error: cannot initialize cpu_probe "
			"attributes\n");
		goto out_probe_sources_init;
	}

	for (i=0; i<num_online_cpus(); i++) {
		cpu_used_prev[i] = 0;
		cpu_total_prev[i] = 0;
	}
	cpu_probe = scheduler_probe_create(&cpu_probe_type, CPU_PROBE_NAME,
					   cpu_probe_sources, NULL);
	if (cpu_probe == NULL){
		printk(KERN_ERR "error: cpu_probe creation failed!\n");
		goto out_kmalloc;
	}

	// perform first measurement
	measure_cpu();
	for (i=0; i<num_online_cpus(); i++) {
		probe_data_prev[i] = probe_data[i];
	}

	err = scheduler_probe_register(cpu_probe);
	if (err)
		goto err_register;

	return 0;

err_register:
	scheduler_probe_free(cpu_probe);
out_probe_sources_init:
	if (cpu_probe_sources[0] != NULL)
		scheduler_probe_source_free(cpu_probe_sources[0]);

out_kmalloc:
	if (probe_data)
		kfree(probe_data);
	if (probe_data_prev)
		kfree(probe_data_prev);
	if (cpu_used)
		kfree(cpu_used);
	if (cpu_total)
		kfree(cpu_total);
	if (cpu_used_prev)
		kfree(cpu_used_prev);
	if (cpu_total_prev)
		kfree(cpu_total_prev);

	return err;
}

void cleanup_module()
{
	int i;

	PDEBUG(KERN_INFO "cpu_probe cleanup function called!\n");
	scheduler_probe_unregister(cpu_probe);
	scheduler_probe_free(cpu_probe);
	for (i = 0; cpu_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(cpu_probe_sources[i]);
	kfree(probe_data);
	kfree(probe_data_prev);
	kfree(cpu_used);
	kfree(cpu_total);
	kfree(cpu_used_prev);
	kfree(cpu_total_prev);
}
