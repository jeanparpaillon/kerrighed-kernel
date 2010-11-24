/**
 * Kerrighed Local CPU Informations Probe module
 *
 * Copyright (c) 2009 - Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>
 *
 * Part of Mathieu Dabert's API (Copyright (c) 2008)
 **/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/cpufreq.h>

#include <kerrighed/scheduler/probe.h>

static struct scheduler_probe *cpuspeed_probe;

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("Local CPU Informations probe");

static unsigned int read_cpu_freq(unsigned int cpuid)
{
	unsigned int khz;

	khz = cpufreq_quick_get(cpuid);
	/* same idea than in arch/x86/kernel/cpu/proc.c:108 */
	if (!khz)
		khz = cpu_khz;

	return khz;
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET(cpu_connected_probe, int, value_p, nr)
{
	*value_p = num_online_cpus();
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(cpu_connected_probe, page)
{
	return sprintf(page, "%d\n", num_online_cpus());
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(cpu_connected_probe),
	.SCHEDULER_PROBE_SOURCE_GET(cpu_connected_probe),
	.SCHEDULER_PROBE_SOURCE_SHOW(cpu_connected_probe),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(cpu_connected_probe, int),
END_SCHEDULER_PROBE_SOURCE_TYPE(cpu_connected_probe);

DEFINE_SCHEDULER_PROBE_SOURCE_GET_WITH_INPUT(cpu_speed_probe, unsigned int, value_p, nr, unsigned int, idx_p, in_nr)
{
	int i;

	if (in_nr) /* Only returns the CPU queried */
		for (i = 0; i < in_nr && i < nr; i++) {
			if (cpu_online(idx_p[i])) {
				*value_p++ = read_cpu_freq(idx_p[i]);
			} else
				return -EINVAL;
		}
	else	/* Show as many CPUs possible */
		for (i = 0; i < nr && cpu_online(i); i++) {
			*value_p++ = read_cpu_freq(i);
		}
	return i;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(cpu_speed_probe, page)
{
	size_t size = SCHEDULER_PROBE_SOURCE_ATTR_SIZE;
	ssize_t	count;
	int tmp_count;
	int i;
	unsigned int khz;

	khz = cpufreq_quick_get(0);
	/* same idea than in arch/x86/kernel/cpu/proc.c:108 */
	if (khz == 0)
		khz = cpu_khz;

	tmp_count = snprintf(page, size, "CPU#%d: %ukHz\n", 0, khz);
	count = tmp_count;

	for (i = 1; tmp_count >= 0 && count+1 < size && cpu_online(i); i++) {
		khz = read_cpu_freq(i);

		tmp_count = snprintf(page + count, size - count, "CPU#%d: %ukHz\n", i, khz);
		if (tmp_count >= 0)
			count += tmp_count;
	}

	return (tmp_count < 0) ? tmp_count : min( (size_t)count, size );
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(cpu_speed_probe),
	.SCHEDULER_PROBE_SOURCE_GET(cpu_speed_probe),
	.SCHEDULER_PROBE_SOURCE_SHOW(cpu_speed_probe),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(cpu_speed_probe, unsigned int),
	.SCHEDULER_PROBE_SOURCE_PARAM_TYPE(cpu_speed_probe, unsigned int),
END_SCHEDULER_PROBE_SOURCE_TYPE(cpu_speed_probe);

static struct scheduler_probe_source *cpuspeed_probe_sources[3];

static SCHEDULER_PROBE_TYPE(cpuspeed_probe_type, NULL, NULL);

static int __init cpuspeed_probe_init(void)
{
	int err = -ENOMEM;

	cpuspeed_probe_sources[0] = scheduler_probe_source_create(&cpu_connected_probe_type, "connected");
	cpuspeed_probe_sources[1] = scheduler_probe_source_create(&cpu_speed_probe_type, "speed");
	cpuspeed_probe_sources[2] = NULL;

	if (!cpuspeed_probe_sources[0] || !cpuspeed_probe_sources[1]) {
		printk(KERN_ERR "error: cpuspeed_probe_sources creation failed!\n");
		goto out_kmalloc;
	}

	cpuspeed_probe = scheduler_probe_create(&cpuspeed_probe_type, "cpuspeed_probe", cpuspeed_probe_sources, NULL);

	if (!cpuspeed_probe) {
		printk(KERN_ERR "error: cpuspeed_probe creation failed!\n");
		goto out_kmalloc;
	}

	err = scheduler_probe_register(cpuspeed_probe);
	if (err)
		goto err_register;

	printk(KERN_INFO "cpuspeed_probe loaded.\n");

	return 0;

err_register:
	scheduler_probe_free(cpuspeed_probe);
out_kmalloc:
	if (cpuspeed_probe_sources[0])
		scheduler_probe_source_free(cpuspeed_probe_sources[0]);
	if (cpuspeed_probe_sources[1])
		scheduler_probe_source_free(cpuspeed_probe_sources[1]);

	return err;
}

static void __exit cpuspeed_probe_exit(void)
{
	int i;

	scheduler_probe_unregister(cpuspeed_probe);
	scheduler_probe_free(cpuspeed_probe);

	for (i = 0; cpuspeed_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(cpuspeed_probe_sources[i]);
}

module_init(cpuspeed_probe_init);
module_exit(cpuspeed_probe_exit);
