/*
 *  kerrighed/scheduler/probes/mem_probe.c
 *
 *  Copyright (C) 2007 Marko Novak - Xlab
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <kerrighed/scheduler/probe.h>

#include "mem_probe.h"

#define K(x) ((x) << (PAGE_SHIFT - 10))

static mem_probe_data_t probe_data;
static mem_probe_data_t probe_data_prev;

MODULE_LICENSE("LGPL");
MODULE_AUTHOR("Marko Novak <marko.novak@xlab.si>, "
	      "Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Memory probe module.");

static struct scheduler_probe *mem_probe;
static int mem_free_active = 1;
static int mem_total_active = 1;

#undef DEBUG_MONITOR

#ifdef DEBUG_MONITOR
#define PDEBUG(format, args...) printk(format, ## args)
#else
#define PDEBUG(format, args...)
#endif

DEFINE_SCHEDULER_PROBE_SOURCE_GET(mem_free, unsigned long, value_p, nr)
{
	//spin_lock(&probe_data.lock);
	*value_p = K(probe_data.ram_free);
	//spin_unlock(&probe_data.lock);
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(mem_free, page)
{
	ssize_t ret;

	//spin_lock(&probe_data.lock);
	ret = sprintf(page, "%lu\n", K(probe_data.ram_free));
	//spin_unlock(&probe_data.lock);

	return ret;
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET(mem_total, unsigned long, value_p, nr)
{
	//spin_lock(&probe_data.lock);
	*value_p = K(probe_data.ram_total);
	//spin_unlock(&probe_data.lock);
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(mem_total, page)
{
	ssize_t ret;

	//spin_lock(&probe_data.lock);
	ret = sprintf(page, "%lu\n", K(probe_data.ram_total));
	//spin_unlock(&probe_data.lock);

	return ret;
}

static void measure_mem(void)
{
	struct sysinfo meminfo;

	PDEBUG("mem_probe: start.\n");

	si_meminfo(&meminfo);

	//spin_lock(&probe_data.lock);
	probe_data.ram_free = meminfo.freeram;
	probe_data.ram_total = meminfo.totalram;
	//spin_unlock( &(probe_data.lock) );

	PDEBUG("mem_probe: finished.\n");
}

DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(mem_total)
{
	int isChanged = 0;

	if (mem_total_active &&
	    probe_data.ram_total != probe_data_prev.ram_total) {
		isChanged = 1;

		probe_data_prev.ram_total = probe_data.ram_total;
	}

	return isChanged;
}

static ssize_t mem_total_active_attr_show(char *page)
{
	return sprintf(page, "%d", mem_total_active);
}

static ssize_t mem_total_active_attr_store(const char *page, size_t count)
{
	int new_active;
	char *last_read;

	new_active = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	mem_total_active = !!new_active;
	return count;
}

static SCHEDULER_PROBE_SOURCE_ATTRIBUTE(mem_total_active_attr, "active", 0644,
					mem_total_active_attr_show,
					mem_total_active_attr_store);

static struct scheduler_probe_source_attribute *mem_total_attrs[] = {
	&mem_total_active_attr,
	NULL
};

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(mem_total),
	.SCHEDULER_PROBE_SOURCE_GET(mem_total),
	.SCHEDULER_PROBE_SOURCE_SHOW(mem_total),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(mem_total, unsigned long),
	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(mem_total),
	.SCHEDULER_PROBE_SOURCE_ATTRS(mem_total, mem_total_attrs),
END_SCHEDULER_PROBE_SOURCE_TYPE(mem_total);

DEFINE_SCHEDULER_PROBE_SOURCE_HAS_CHANGED(mem_free)
{
        int isChanged = 0;

        if (mem_free_active
	    && probe_data.ram_free != probe_data_prev.ram_free) {
                isChanged = 1;

                probe_data_prev.ram_free = probe_data.ram_free;
        }

        return isChanged;
}

static ssize_t mem_free_active_attr_show(char *page)
{
	return sprintf(page, "%d", mem_free_active);
}

static ssize_t mem_free_active_attr_store(const char *page, size_t count)
{
	int new_active;
	char *last_read;

	new_active = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	mem_free_active = !!new_active;
	return count;
}

static SCHEDULER_PROBE_SOURCE_ATTRIBUTE(mem_free_active_attr, "active", 0644,
					mem_free_active_attr_show,
					mem_free_active_attr_store);

static struct scheduler_probe_source_attribute *mem_free_attrs[] = {
	&mem_free_active_attr,
	NULL
};

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(mem_free),
	.SCHEDULER_PROBE_SOURCE_GET(mem_free),
	.SCHEDULER_PROBE_SOURCE_SHOW(mem_free),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(mem_free, unsigned long),
	.SCHEDULER_PROBE_SOURCE_HAS_CHANGED(mem_free),
	.SCHEDULER_PROBE_SOURCE_ATTRS(mem_free, mem_free_attrs),
END_SCHEDULER_PROBE_SOURCE_TYPE(mem_free);

static struct scheduler_probe_source *mem_probe_sources[3];

static SCHEDULER_PROBE_TYPE(mem_probe_type, NULL, measure_mem);

int init_module()
{
	int err = -ENOMEM;

	mem_probe_sources[0] = scheduler_probe_source_create(&mem_free_type,
							     "ram_free");
	mem_probe_sources[1] = scheduler_probe_source_create(&mem_total_type,
							     "ram_total");
	mem_probe_sources[2] = NULL;

	if (mem_probe_sources[0]==NULL || mem_probe_sources[1]==NULL) {
		printk(KERN_ERR "error: cannot initialize mem_probe "
			"attributes\n");
		goto out_kmalloc;
	}

	mem_probe = scheduler_probe_create(&mem_probe_type, MEM_PROBE_NAME,
					   mem_probe_sources, NULL);
	if (mem_probe == NULL) {
		printk(KERN_ERR "error: mem_probe creation failed!\n");
		goto out_kmalloc;
	}

	// perform first measurement
	measure_mem();
	probe_data_prev = probe_data;

	err = scheduler_probe_register(mem_probe);
	if (err)
		goto err_register;

	return 0;

err_register:
	scheduler_probe_free(mem_probe);
out_kmalloc:
	if (mem_probe_sources[0] != NULL)
		scheduler_probe_source_free(mem_probe_sources[0]);
	if (mem_probe_sources[1] != NULL)
		scheduler_probe_source_free(mem_probe_sources[1]);

	return err;
}

void cleanup_module()
{
	int i;
	PDEBUG(KERN_INFO "mem_probe cleanup function called!\n");
	scheduler_probe_unregister(mem_probe);
	scheduler_probe_free(mem_probe);
	for (i = 0; mem_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(mem_probe_sources[i]);
}
