/**
 * Kerrighed User Probe module
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

#include <kerrighed/scheduler/probe.h>

#include "local_user_presence.h"

static struct scheduler_probe *user_probe;

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("Local user presence probe");

DEFINE_SCHEDULER_PROBE_SOURCE_GET(user_connected_probe, unsigned int, value_p, nr)
{
	*value_p = local_user_presence_user_connected();
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(user_connected_probe, page)
{
	return sprintf(page, "%u\n", local_user_presence_user_connected());
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(user_connected_probe),
	.SCHEDULER_PROBE_SOURCE_GET(user_connected_probe),
	.SCHEDULER_PROBE_SOURCE_SHOW(user_connected_probe),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(user_connected_probe, unsigned int),
END_SCHEDULER_PROBE_SOURCE_TYPE(use_connected_probe);

static struct scheduler_probe_source *user_probe_sources[2];

static SCHEDULER_PROBE_TYPE(user_probe_type, NULL, NULL);

static int __init user_probe_init(void)
{
	int err = -ENOMEM;

	user_probe_sources[0] = scheduler_probe_source_create(&user_connected_probe_type, "connected");
	user_probe_sources[1] = NULL;

	if (!user_probe_sources[0]) {
		printk(KERN_ERR "error: user_probe source creation failed!\n");
		goto out_source;
	}

	user_probe = scheduler_probe_create(&user_probe_type, "user_probe", user_probe_sources, NULL);

	if (!user_probe) {
		printk(KERN_ERR "error: user_probe creation failed!\n");
		goto out_kmalloc;
	}

	err = scheduler_probe_register(user_probe);
	if (err)
		goto err_register;

	printk(KERN_INFO "user_probe loaded.\n");

	return 0;

err_register:
	scheduler_probe_free(user_probe);
out_kmalloc:
	scheduler_probe_source_free(user_probe_sources[0]);
out_source:

	return err;
}

static void __exit user_probe_exit(void)
{
	int i;
	printk(KERN_INFO "user_probe cleanup function called!\n");
	scheduler_probe_unregister(user_probe);
	scheduler_probe_free(user_probe);

	for (i = 0; user_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(user_probe_sources[i]);
}

module_init(user_probe_init);
module_exit(user_probe_exit);
