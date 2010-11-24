/* *
 * Kerrighed Local Unix active tasks probe module
 *
 * Copyright (c) 2009 - Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>
 *
 * Part of Mathieu Dabert's API (Copyright (c) 2008)
 * */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/jiffies.h>

#include <kerrighed/pid.h>
#include <kerrighed/scheduler/hooks.h>
#include <kerrighed/scheduler/probe.h>
#include <kerrighed/scheduler/info.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("General load module probe.");

static struct scheduler_probe *load_probe;

struct load_probe_info {
	struct krg_sched_module_info module_info;
	u64 entry_jiffies;
	u64 exit_jiffies;
};

static
inline
struct load_probe_info *
to_load_probe_info(struct krg_sched_module_info *sched_info)
{
	return container_of(sched_info, struct load_probe_info, module_info);
}

static struct notifier_block notif_process_on;
static struct notifier_block notif_process_off;

static void load_probe_init_info(struct task_struct *task, struct load_probe_info *info)
{
	info->entry_jiffies = 0;
	info->exit_jiffies = 0;
}

static struct krg_sched_module_info *load_probe_info_copy(
	struct task_struct *task,
	struct krg_sched_module_info *info)
{
	struct load_probe_info *new_info;

	new_info = kmalloc(sizeof(struct load_probe_info), GFP_KERNEL);
	if (new_info) {
		load_probe_init_info(task, new_info);
		return &new_info->module_info;
	}

	return NULL;
}

static void load_probe_info_free(struct krg_sched_module_info *info)
{
	kfree(to_load_probe_info(info));
}

static struct krg_sched_module_info *load_probe_info_import(
	struct epm_action *action,
	struct ghost *ghost,
	struct task_struct *task)
{
	return load_probe_info_copy(task, NULL);
}

static int load_probe_info_export(
	struct epm_action *action,
	struct ghost *ghost,
	struct krg_sched_module_info *info)
{
	return 0;
}

static struct krg_sched_module_info_type load_probe_module_info_type = {
	.name	= "load probe",
	.owner	= THIS_MODULE,
	.copy 	= load_probe_info_copy, /* Called by framework on fork() */
	.free	= load_probe_info_free,
	.import	= load_probe_info_import,
	.export	= load_probe_info_export
};

static struct load_probe_info *get_load_probe_info(struct task_struct *task)
{
	struct krg_sched_module_info *mod_info;

	mod_info = krg_sched_module_info_get(task, &load_probe_module_info_type);
	if (mod_info)
		return to_load_probe_info(mod_info);

	return NULL;
}

static void load_process_on(struct task_struct *task)
{
	struct load_probe_info *p;

	rcu_read_lock();
	p = get_load_probe_info(task);
	if (p)
		p->entry_jiffies = get_jiffies_64();
	rcu_read_unlock();
}

static void load_process_off(struct task_struct *task)
{
	struct load_probe_info *p;

	rcu_read_lock();
	p = get_load_probe_info(task);
	if (p)
		p->exit_jiffies = get_jiffies_64();
	rcu_read_unlock();
}

static int kmcb_process_on(struct notifier_block *notifier, unsigned long arg, void *data)
{
	load_process_on(data);
	return NOTIFY_DONE;
}

static int kmcb_process_off(struct notifier_block *notifier, unsigned long arg, void *data)
{
	load_process_off(data);
	return NOTIFY_DONE;
}

unsigned int count_process_jiffies(struct task_struct *task)
{
	struct load_probe_info *p;
	unsigned int retval;

	/*
	  Our goal: compute the elapsed time of a process in the runqueue,
	  since the last time it entered TASK_RUNNING state.
	*/
	rcu_read_lock();
	p = get_load_probe_info(task);
	if (p) {
		if (p->exit_jiffies == 0) {
			if (p->entry_jiffies == 0)
				retval = 0;
			else if (get_jiffies_64() < p->entry_jiffies)
				retval = 0;
			else	retval = get_jiffies_64() - p->entry_jiffies;
		} else { /* p->exit_jiffies != 0 */
			if (p->exit_jiffies > p->entry_jiffies)
				retval = p->exit_jiffies - p->entry_jiffies;
			else	retval = get_jiffies_64() - p->entry_jiffies;	/* p->exit_jiffies <= p->entry_jiffies */
		}
	} else {
		retval = 0;
	}
	rcu_read_unlock();

	return retval;
}

unsigned long count_active_tasks_on_node(void)
{
	return nr_running();
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET(active_tasks, unsigned long, value_p, nr)
{
	*value_p = count_active_tasks_on_node();
	return 1;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(active_tasks, page)
{
	return sprintf(page, "%lu\n", count_active_tasks_on_node());
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(active_tasks),
	.SCHEDULER_PROBE_SOURCE_GET(active_tasks),
	.SCHEDULER_PROBE_SOURCE_SHOW(active_tasks),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(active_tasks, unsigned long),
END_SCHEDULER_PROBE_SOURCE_TYPE(active_tasks);

static unsigned int get_process_jiffies_from_task(struct task_struct *task)
{
	return count_process_jiffies(task);
}

static unsigned int get_process_jiffies_from_pid(pid_t process)
{
	struct task_struct *task;

	task = find_task_by_kpid(process);
	if (!task)
		return 0;

	return get_process_jiffies_from_task(task);
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(value_process_jiffies, page)
{
	size_t size = SCHEDULER_PROBE_SOURCE_ATTR_SIZE;
	ssize_t count = 0;
	int tmp_count = 0;
	struct task_struct *tsk;

	rcu_read_lock();

	for_each_process(tsk) {
		tmp_count = snprintf(page + count, size - count,
				"%d: %u\n", task_pid_knr(tsk),
				get_process_jiffies_from_task(tsk));

		if (tmp_count >= 0)
			count += tmp_count;
	}

	rcu_read_unlock();

	return (tmp_count < 0) ? tmp_count : min( (size_t) count, size );
}

DEFINE_SCHEDULER_PROBE_SOURCE_GET_WITH_INPUT(value_process_jiffies, unsigned int, value_p, nr, pid_t, in_value_p, in_nr)
{
	int i;

	rcu_read_lock();

	for (i = 0; i < in_nr && i < nr; i++)
		value_p[i] = get_process_jiffies_from_pid(in_value_p[i]);

	rcu_read_unlock();

	return i;
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(value_process_jiffies),
	.SCHEDULER_PROBE_SOURCE_GET(value_process_jiffies),
	.SCHEDULER_PROBE_SOURCE_SHOW(value_process_jiffies),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(value_process_jiffies, unsigned int),
	.SCHEDULER_PROBE_SOURCE_PARAM_TYPE(value_process_jiffies, pid_t),
END_SCHEDULER_PROBE_SOURCE_TYPE(value_process_load);

static struct scheduler_probe_source *load_probe_sources[3];

static SCHEDULER_PROBE_TYPE(load_probe_type, NULL, NULL);

static int __init load_probe_init(void)
{
	int err = -ENOMEM;

	load_probe_sources[0] = scheduler_probe_source_create(&active_tasks_type, "active_tasks");
	load_probe_sources[1] = scheduler_probe_source_create(&value_process_jiffies_type, "process_jiffies");
	load_probe_sources[2] = NULL;

	if (!load_probe_sources[0] || !load_probe_sources[1]) {
		printk(KERN_ERR "error: load_probe sources creation failed!\n");
		goto out_sources;
	}

	load_probe = scheduler_probe_create(&load_probe_type, "load_probe", load_probe_sources, NULL);

	if (!load_probe) {
		printk(KERN_ERR "error: load_probe creation failed!\n");
		goto out_kmalloc;
	}

	notif_process_on.notifier_call = kmcb_process_on;
	notif_process_off.notifier_call = kmcb_process_off;

	err = atomic_notifier_chain_register(&kmh_process_on, &notif_process_on);
	if (err)
		goto err_hookon_reg;

	err = atomic_notifier_chain_register(&kmh_process_off, &notif_process_off);
	if (err)
		goto err_hookoff_reg;

	err = krg_sched_module_info_register(&load_probe_module_info_type);
	if (err)
		goto err_mod_info;

	printk(KERN_INFO "load_probe: module_info registered.\n");

	err = scheduler_probe_register(load_probe);
	if (err)
		goto err_register;

	printk(KERN_INFO "load_probe loaded.\n");

out:
	return err;

err_mod_info:
	printk(KERN_ERR "load_probe: error while registering module info.\n");
	atomic_notifier_chain_unregister(&kmh_process_off, &notif_process_off);
err_hookoff_reg:
	atomic_notifier_chain_unregister(&kmh_process_on, &notif_process_on);
err_hookon_reg:
	scheduler_probe_free(load_probe);
out_sources:
out_kmalloc:
	if (load_probe_sources[0])
		scheduler_probe_source_free(load_probe_sources[0]);
	if (load_probe_sources[1])
		scheduler_probe_source_free(load_probe_sources[1]);
	goto out;

err_register:
	printk(KERN_ERR "load_probe: error while registering probe.\n");
	printk(KERN_ERR "load_probe: Module cannot cleanly self-unload.\nPlease unload the module.\n");
	err = 0; /* Prevent the module from unload */
	goto out;
}

static void __exit load_probe_exit(void)
{
	int i;

	printk(KERN_INFO "load_probe cleanup function called!\n");

	scheduler_probe_unregister(load_probe);

	krg_sched_module_info_unregister(&load_probe_module_info_type);
	atomic_notifier_chain_unregister(&kmh_process_off, &notif_process_off);
	atomic_notifier_chain_unregister(&kmh_process_on, &notif_process_on);

	scheduler_probe_free(load_probe);

	for (i = 0; load_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(load_probe_sources[i]);
}

module_init(load_probe_init);
module_exit(load_probe_exit);
