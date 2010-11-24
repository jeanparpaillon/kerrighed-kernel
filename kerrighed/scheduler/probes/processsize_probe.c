/* *
 * Kerrighed Local CPU Informations Probe module
 *
 * Copyright (c) 2009 - Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>
 *
 * Part of Mathieu Dabert's API (Copyright (c) 2008)
 * */

#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/threads.h>

#include <kerrighed/pid.h>
#include <kerrighed/scheduler/probe.h>

static struct scheduler_probe *processsize_probe;

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexandre Lissy <alexandre.lissy@etu.univ-tours.fr>");
MODULE_DESCRIPTION("Process Size module probe");

DEFINE_SCHEDULER_PROBE_SOURCE_GET_WITH_INPUT(process_total_size, pid_t, value_p, nr, unsigned long, idx_p, in_nr)
{
	int i = 0;
	struct task_struct *ts;

	if (in_nr) { /* Only returns the process queried */
		for (i = 0; i < in_nr && i < nr; i++) {
			rcu_read_lock();
			ts = find_task_by_kpid(idx_p[i]);
			/* tsk->mm can be NULL
			 * cf. http://lkml.indiana.edu/hypermail/linux/kernel/0111.3/1188.html
			 *
			 * > Hey,
			 * >
			 * > I found in some code checks for task_struct.mm being NULL.
			 * > When can task_struct.mm of a process be NULL except right before the
			 * > process-kill?
			 *
			 * For kernel threads that run in lazy-mm mode. It allows a much cheaper context
			 * switch into kernel threads.
			 * */
			if (ts) {
				task_lock(ts);
				if (ts->mm)
					*value_p++ = ts->mm->total_vm;
				else
					*value_p++ = 0;
				task_unlock(ts);
			} else {
				*value_p++ = 0;
			}
			rcu_read_unlock();
		}
	}

	return i;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(process_total_size, page)
{
	struct task_struct *tsk;

	size_t size = SCHEDULER_PROBE_SOURCE_ATTR_SIZE;
	ssize_t count = 0;
	int tmp_count = 0;

	printk(KERN_INFO "process_total_size_show function called.\n");

	rcu_read_lock();

	for_each_process(tsk) {
		/* tsk->mm can be NULL
		 * cf. http://lkml.indiana.edu/hypermail/linux/kernel/0111.3/1188.html
		 *
		 * > Hey,
		 * >
		 * > I found in some code checks for task_struct.mm being NULL.
		 * > When can task_struct.mm of a process be NULL except right before the
		 * > process-kill?
		 *
		 * For kernel threads that run in lazy-mm mode. It allows a much cheaper context
		 * switch into kernel threads.
		 * */
		task_lock(tsk);
		if (tsk->mm) {
			tmp_count = snprintf(page + count, size - count, "Process %d: %lu pages\n", task_pid_knr(tsk), tsk->mm->total_vm);

			if (tmp_count >= 0)
				count += tmp_count;
		}
		task_unlock(tsk);
	}

	rcu_read_unlock();

	return (tmp_count < 0) ? tmp_count : min( (size_t) count, size );
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(process_total_size),
	.SCHEDULER_PROBE_SOURCE_GET(process_total_size),
	.SCHEDULER_PROBE_SOURCE_SHOW(process_total_size),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(process_total_size, unsigned long),
	.SCHEDULER_PROBE_SOURCE_PARAM_TYPE(process_total_size, pid_t),
END_SCHEDULER_PROBE_SOURCE_TYPE(process_total_size);

static struct scheduler_probe_source *processsize_probe_sources[2];

static SCHEDULER_PROBE_TYPE(processsize_probe_type, NULL, NULL);

static int __init processsize_probe_init(void)
{
	int err = -ENOMEM;

	processsize_probe_sources[0] = scheduler_probe_source_create(&process_total_size_type, "total_vm");
	if (!processsize_probe_sources[0]) {
		printk(KERN_ERR "processsize_probe: Error while scheduler_probe_source_create\n");
		goto err_probe_create;
	}

	processsize_probe_sources[1] = NULL;

	processsize_probe = scheduler_probe_create(&processsize_probe_type, "processsize_probe", processsize_probe_sources, NULL);

	if (!processsize_probe) {
		printk(KERN_ERR "error: processsize_probe creation failed!\n");
		goto out_kmalloc;
	}

	err = scheduler_probe_register(processsize_probe);
	if (err)
		goto err_register;

	printk(KERN_INFO "processsize_probe loaded.\n");

	return 0;

err_register:
	scheduler_probe_free(processsize_probe);
out_kmalloc:
	scheduler_probe_source_free(processsize_probe_sources[0]);
err_probe_create:

	return err;
}

static void __exit processsize_probe_exit(void)
{
	int i;

	printk(KERN_INFO "processsize_probe cleanup function called!\n");
	scheduler_probe_unregister(processsize_probe);
	scheduler_probe_free(processsize_probe);

	for (i = 0; processsize_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(processsize_probe_sources[i]);
}

module_init(processsize_probe_init);
module_exit(processsize_probe_exit);
