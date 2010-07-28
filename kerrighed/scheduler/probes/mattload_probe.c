/**
 * Kerrighed Local Unix active tasks probe module
 *
 * Copyright (c) 2009 - Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>
 *
 * Matteo's Load Measure is Copyright (c) 2008 - Matthieu Pérotin.
 * More informations available at :
 * http://portail.scd.univ-tours.fr/search*frf/X?PEROTIN,%20MATTHIEU&m=t&m=u
 **/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/sched.h>

#include <kerrighed/scheduler/port.h>
#include <kerrighed/scheduler/probe.h>

static struct scheduler_probe *mattload_probe;
static struct scheduler_port port_active_tasks;
static struct scheduler_port port_cpu_speed;
static struct scheduler_port port_cpu_connected;
static struct scheduler_port port_user_connected;
static int mattload_param_k = 1;
static int mattload_multiply_factor = 1000000;

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("Computing node load using Matteo's formula.");

static BEGIN_SCHEDULER_PORT_TYPE(port_active_tasks),
	.SCHEDULER_PORT_VALUE_TYPE(port_active_tasks, unsigned long),
END_SCHEDULER_PORT_TYPE(port_active_tasks);

static BEGIN_SCHEDULER_PORT_TYPE(port_cpu_speed),
	.SCHEDULER_PORT_VALUE_TYPE(port_cpu_speed, unsigned int),
	.SCHEDULER_PORT_PARAM_TYPE(port_cpu_speed, unsigned int),
END_SCHEDULER_PORT_TYPE(port_cpu_speed);

static BEGIN_SCHEDULER_PORT_TYPE(port_cpu_connected),
	.SCHEDULER_PORT_VALUE_TYPE(port_cpu_connected, int),
END_SCHEDULER_PORT_TYPE(port_cpu_connected);

static BEGIN_SCHEDULER_PORT_TYPE(port_user_connected),
	.SCHEDULER_PORT_VALUE_TYPE(port_user_connected, unsigned int),
END_SCHEDULER_PORT_TYPE(port_user_connected);

static unsigned int matteo_load_calc(int calc_load_increment)
{
	/* Matteo's way to compute the load. */
	int err;
	unsigned int load;
	unsigned int state_mj;
	unsigned int sum_xij;
	unsigned int cpu_speed;
	int cpu_connected;

	/**
	 * Lockdep is disable because it arises false warning when a probe
	 * requests data from another probe.
	 * This means that each scheduler_port_get_value() code following
	 * was arising a false lockdep error.
	 **/

	/* (1 + K*(state(mj)))((sum Xij)/speed(mj)) */
	/* Disable lockdep checking, as it arises false warning. */
	lockdep_off();
	err = scheduler_port_get_value(&port_cpu_speed, &cpu_speed, 1, NULL, 0);
	/* Re-enable lockdep checking. */
	lockdep_on();
	if (err < 0)
		goto err_cpu_speed;

	/* Disable lockdep checking, as it arises false warning. */
	lockdep_off();
	err = scheduler_port_get_value(&port_cpu_connected, &cpu_connected, 1, NULL, 0);
	/* Re-enable lockdep checking. */
	lockdep_on();
	if (err < 0)
		goto err_cpu_connected;

	/* Disable lockdep checking, as it arises false warning. */
	lockdep_off();
	err = scheduler_port_get_value(&port_user_connected, &state_mj, 1, NULL, 0);
	/* Re-enable lockdep checking. */
	lockdep_on();
	if (err < 0)
		goto err_user_connected;

	if (calc_load_increment == 0) {
		/* Disable lockdep checking, as it arises false warning. */
		lockdep_off();
		err = scheduler_port_get_value(&port_active_tasks, &sum_xij, 1, NULL, 0);
		/* Re-enable lockdep checking. */
		lockdep_on();
		if (err < 0)
			goto err_active_tasks;
	} else {
		sum_xij = 1;
	}

	/* K : parameter
	 * state(mj) => user_probe
	 * sum Xij => load_probe
	 * speed(mj) => cpuspeed_probe
	 * */

	/* Convert to MHz */
	cpu_speed /= 1000;

	load = ((1 + mattload_param_k*(state_mj))) * ((mattload_multiply_factor*sum_xij)/(cpu_speed*cpu_connected));

	return load;

err_cpu_speed:
	printk(KERN_ERR "mattload: error while reading port : cpu_speed\n");

err_cpu_connected:
	printk(KERN_ERR "mattload: error while reading port : cpu_connected\n");

err_user_connected:
	printk(KERN_ERR "mattload: error while reading port : user_connected\n");

err_active_tasks:
	printk(KERN_ERR "mattload: error while reading port : active_tasks\n");

	return err;
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET(mattload, unsigned int, value_p, nr)
{
	unsigned int value = matteo_load_calc(0);

	if ((int)value < 0)
		return (int)value;
	*value_p = value;

	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(mattload, page)
{
	unsigned int load = matteo_load_calc(0);

	if ((int)load < 0)
		return (int)load;

	return sprintf(page, "%u\n", load);
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(mattload),
	.SCHEDULER_PROBE_SOURCE_GET(mattload),
	.SCHEDULER_PROBE_SOURCE_SHOW(mattload),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(mattload, unsigned int),
END_SCHEDULER_PROBE_SOURCE_TYPE(mattload);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(loadinc, unsigned int, value_p, nr)
{
	unsigned int value = matteo_load_calc(1);

	if ((int)value < 0)
		return (int)value;
	*value_p = value;

	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(loadinc, page)
{
	unsigned int load = matteo_load_calc(1);

	if ((int)load < 0)
		return (int)load;

	return sprintf(page, "%u\n", load);
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(loadinc),
	.SCHEDULER_PROBE_SOURCE_GET(loadinc),
	.SCHEDULER_PROBE_SOURCE_SHOW(loadinc),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(loadinc, unsigned int),
END_SCHEDULER_PROBE_SOURCE_TYPE(loadinc);

static struct scheduler_probe_source *mattload_probe_sources[3];

static ssize_t param_k_attr_show (struct scheduler_probe *probe, char *page)
{
	return sprintf(page, "%d\n", mattload_param_k);
}

static ssize_t param_k_attr_store (struct scheduler_probe *probe, const char *page, size_t count)
{
	int new_paramk;
	char *lastread;

	new_paramk = simple_strtoul(page, &lastread, 0);
	if ((lastread - page + 1 < count) || (lastread[1] != '\0' && lastread[1] != '\n'))
	{
		return -EINVAL;
	}

	mattload_param_k = new_paramk;

	return count;
}

static SCHEDULER_PROBE_ATTRIBUTE(
		param_k_attr,
		"param_k",
		S_IRUGO | S_IWUSR,
		param_k_attr_show,
		param_k_attr_store
	);

static ssize_t multiply_factor_attr_show (struct scheduler_probe *probe, char *page)
{
	return sprintf(page, "%d\n", mattload_multiply_factor);
}

static ssize_t multiply_factor_attr_store (struct scheduler_probe *probe, const char *page, size_t count)
{
	int new_mfact;
	char *lastread;

	new_mfact = simple_strtoul(page, &lastread, 0);
	if ((lastread - page + 1 < count) || (lastread[1] != '\0' && lastread[1] != '\n'))
	{
		return -EINVAL;
	}

	mattload_multiply_factor = new_mfact;

	return count;
}

static SCHEDULER_PROBE_ATTRIBUTE(
		multiply_factor_attr,
		"multiply_factor",
		S_IRUGO | S_IWUSR,
		multiply_factor_attr_show,
		multiply_factor_attr_store
	);

static struct scheduler_probe_attribute *mattload_probe_attributes[] = {
	&param_k_attr,
	&multiply_factor_attr,
	NULL
};

static SCHEDULER_PROBE_TYPE(mattload_probe_type, mattload_probe_attributes, NULL);

static int mattload_ports_init(void)
{
	int err;

	/* First, initialize ports type */
	err = scheduler_port_type_init(&port_active_tasks_type, NULL);
	if (err)
		goto err_type_active_tasks;

	err = scheduler_port_type_init(&port_cpu_speed_type, NULL);
	if (err)
		goto err_type_cpu_speed;

	err = scheduler_port_type_init(&port_cpu_connected_type, NULL);
	if (err)
		goto err_type_cpu_connected;

	err = scheduler_port_type_init(&port_user_connected_type, NULL);
	if (err)
		goto err_type_user_connected;

	err = scheduler_port_init(&port_active_tasks, "active_tasks", &port_active_tasks_type, NULL, NULL);
	if (err)
		goto err_active_tasks;

	err = scheduler_port_init(&port_cpu_speed, "cpu_speed", &port_cpu_speed_type, NULL, NULL);
	if (err)
		goto err_cpu_speed;

	err = scheduler_port_init(&port_cpu_connected, "cpu_connected", &port_cpu_connected_type, NULL, NULL);
	if (err)
		goto err_cpu_connected;

	err = scheduler_port_init(&port_user_connected, "user_connected", &port_user_connected_type, NULL, NULL);
	if (err)
		goto err_user_connected;

	return 0;

err_user_connected:
	scheduler_port_cleanup(&port_cpu_connected);
err_cpu_connected:
	scheduler_port_cleanup(&port_cpu_speed);
err_cpu_speed:
	scheduler_port_cleanup(&port_active_tasks);
err_active_tasks:
	scheduler_port_type_cleanup(&port_user_connected_type);
err_type_user_connected:
	scheduler_port_type_cleanup(&port_cpu_connected_type);
err_type_cpu_connected:
	scheduler_port_type_cleanup(&port_cpu_speed_type);
err_type_cpu_speed:
	scheduler_port_type_cleanup(&port_active_tasks_type);
err_type_active_tasks:
	printk(KERN_ERR "matteoload_probe: Cannot init ports.\n");
	return err;
}

static int mattload_ports_exit(void)
{
	scheduler_port_cleanup(&port_active_tasks);
	scheduler_port_cleanup(&port_cpu_speed);
	scheduler_port_cleanup(&port_cpu_connected);
	scheduler_port_cleanup(&port_user_connected);
	scheduler_port_type_cleanup(&port_active_tasks_type);
	scheduler_port_type_cleanup(&port_cpu_speed_type);
	scheduler_port_type_cleanup(&port_cpu_connected_type);
	scheduler_port_type_cleanup(&port_user_connected_type);

	return 0;
}

static int __init mattload_probe_init(void)
{
	int err = -ENOMEM;
	struct config_group *def_groups[5];

	err = mattload_ports_init();
	if (err < 0) {
		return err;
	}

	/* Initialize default config groups */
	def_groups[0] = scheduler_port_config_group(&port_active_tasks);
	def_groups[1] = scheduler_port_config_group(&port_cpu_speed);
	def_groups[2] = scheduler_port_config_group(&port_cpu_connected);
	def_groups[3] = scheduler_port_config_group(&port_user_connected);
	def_groups[4] = NULL;

	mattload_probe_sources[0] = scheduler_probe_source_create(&mattload_type, "mattload");
	mattload_probe_sources[1] = scheduler_probe_source_create(&loadinc_type, "load_increment");
	mattload_probe_sources[2] = NULL;

	if (!mattload_probe_sources[0] || !mattload_probe_sources[1]) {
		printk(KERN_ERR "error: mattload_probe source creation failed!\n");
		goto out_source;
	}

	mattload_probe = scheduler_probe_create(&mattload_probe_type, "mattload_probe", mattload_probe_sources, def_groups);

	if (!mattload_probe) {
		printk(KERN_ERR "error: mattload_probe creation failed!\n");
		goto out_kmalloc;
	}

	err = scheduler_probe_register(mattload_probe);
	if (err)
		goto err_register;

	printk(KERN_INFO "mattload_probe loaded.\n");

	return 0;

err_register:
	scheduler_probe_free(mattload_probe);
out_kmalloc:
	if (mattload_probe_sources[0])
		scheduler_probe_source_free(mattload_probe_sources[0]);
	if (mattload_probe_sources[1])
		scheduler_probe_source_free(mattload_probe_sources[1]);
out_source:
	mattload_ports_exit();

	return err;
}

static void __exit mattload_probe_exit(void)
{
	int i;

	printk(KERN_INFO "mattload_probe cleanup function called!\n");

	scheduler_probe_unregister(mattload_probe);
	scheduler_probe_free(mattload_probe);

	for (i = 0; mattload_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(mattload_probe_sources[i]);

	mattload_ports_exit();
}

module_init(mattload_probe_init);
module_exit(mattload_probe_exit);
