/*
 *  kerrighed/scheduler/probes/migration_probe.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *
 *  Based on former analyzer.c by Renaud Lottiaux
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 */

#include <linux/module.h>
#include <linux/ktime.h>
#include <kerrighed/migration.h>
#include <kerrighed/scheduler/probe.h>
#include <asm/atomic.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Louis Rilling <Louis.Rilling@kerlabs.com>");
MODULE_DESCRIPTION("Probe tracking migrations");

#undef DBG_MIGRATION_PROBE

#ifdef DBG_MIGRATION_PROBE
#define DEBUG(topic, level, format, args...) \
	printk(KERN_DEBUG "[%s]: " format, __PRETTY_FUNCTION__, ## args);
#else
#define DEBUG(topic, level, format, args...)
#endif

static ktime_t last_migration_raised;
static atomic_t migration_on_going = ATOMIC_INIT(0);

static struct scheduler_probe *migration_probe;
static struct scheduler_probe_source *migration_probe_sources[3];

DEFINE_SCHEDULER_PROBE_SOURCE_GET(migration_probe_last_migration,
				  ktime_t, last_p, nr)
{
	if (likely(nr)) {
		/*
		 * Note: scheduler_probe_source is already locked by the
		 * framework.
		 */
		*last_p = last_migration_raised;
		return 1;
	}
	return 0;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(migration_probe_last_migration, page)
{
	DEBUG(DBG_MIGRATION_PROBE, 2, "called!\n");

	/* TODO: Should convert to wall time to have a meaning in userspace */
	return sprintf(page, "%lld\n", ktime_to_ns(last_migration_raised));
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(migration_probe_last_migration),
	.SCHEDULER_PROBE_SOURCE_GET(migration_probe_last_migration),
	.SCHEDULER_PROBE_SOURCE_SHOW(migration_probe_last_migration),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(migration_probe_last_migration,
					   ktime_t),
END_SCHEDULER_PROBE_SOURCE_TYPE(migration_probe_last_migration);

DEFINE_SCHEDULER_PROBE_SOURCE_GET(migration_probe_migration_ongoing,
				  int, count_p, nr)
{
	if (likely(nr)) {
		*count_p = atomic_read(&migration_on_going);
		return 1;
	}
	return 0;
}

DEFINE_SCHEDULER_PROBE_SOURCE_SHOW(migration_probe_migration_ongoing, page)
{
	DEBUG(DBG_MIGRATION_PROBE, 2, "called!\n");

	return sprintf(page, "%d\n", atomic_read(&migration_on_going));
}

static BEGIN_SCHEDULER_PROBE_SOURCE_TYPE(migration_probe_migration_ongoing),
	.SCHEDULER_PROBE_SOURCE_GET(migration_probe_migration_ongoing),
	.SCHEDULER_PROBE_SOURCE_SHOW(migration_probe_migration_ongoing),
	.SCHEDULER_PROBE_SOURCE_VALUE_TYPE(migration_probe_migration_ongoing,
					   int),
END_SCHEDULER_PROBE_SOURCE_TYPE(migration_probe_migration_ongoing);

static SCHEDULER_PROBE_TYPE(migration_probe_type, NULL, NULL);

static void migration_probe_migration_start(struct task_struct *task)
{
	struct timespec now_ts;

	atomic_inc(&migration_on_going);
	scheduler_probe_source_notify_update(migration_probe_sources[1]);

	ktime_get_ts(&now_ts);
	scheduler_probe_source_lock(migration_probe_sources[0]);
	last_migration_raised = timespec_to_ktime(now_ts);
	scheduler_probe_source_unlock(migration_probe_sources[0]);
	scheduler_probe_source_notify_update(migration_probe_sources[0]);
}

static void kmcb_migration_start(unsigned long arg)
{
	migration_probe_migration_start((struct task_struct *) arg);
}

static void migration_probe_migration_end(struct task_struct *task)
{
	if (!task) {
		atomic_dec(&migration_on_going);
		scheduler_probe_source_notify_update(
			migration_probe_sources[1]);
	}
}

static void kmcb_migration_end(unsigned long arg)
{
	migration_probe_migration_end((struct task_struct *) arg);
}

static void kmcb_migration_aborted(unsigned long arg)
{
	migration_probe_migration_end(NULL);
}

static int probe_not_registered;

int migration_probe_start(void)
{
	int err = -ENOMEM;
	char *err_msg = NULL;

	migration_probe_sources[0] = scheduler_probe_source_create(
		&migration_probe_last_migration_type,
		"last_migration");
	if (!migration_probe_sources[0])
		goto err_last_migration;
	migration_probe_sources[1] = scheduler_probe_source_create(
		&migration_probe_migration_ongoing_type,
		"migration_on_going");
	if (!migration_probe_sources[1])
		goto err_migration_on_going;
	migration_probe_sources[2] = NULL;

	migration_probe = scheduler_probe_create(&migration_probe_type,
						 "migration_probe",
						 migration_probe_sources,
						 NULL);
	if (!migration_probe)
		goto err_probe;

	/*
	 * We cannot call unregister in init, so the system may have to live
	 * with partial hook init until module is unloaded.
	 */
	err = module_hook_register(&kmh_migration_start, kmcb_migration_start,
				   THIS_MODULE);
	if (err)
		goto err_hooks;
	err = module_hook_register(&kmh_migration_end, kmcb_migration_end,
				   THIS_MODULE);
	if (err)
		goto err_other_hooks;
	err = module_hook_register(&kmh_migration_aborted,
				   kmcb_migration_aborted,
				   THIS_MODULE);
	if (err)
		goto err_other_hooks;

	err = scheduler_probe_register(migration_probe);
	if (err)
		goto err_register;

out:
	return err;

err_hooks:
	scheduler_probe_free(migration_probe);
err_probe:
	scheduler_probe_source_free(migration_probe_sources[1]);
err_migration_on_going:
	scheduler_probe_source_free(migration_probe_sources[0]);
err_last_migration:
	goto out;

err_other_hooks:
	if (!err_msg)
		err_msg = "inconsistent hooks initialization";
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

void migration_probe_exit(void)
{
	int i;

	if (!probe_not_registered)
		scheduler_probe_unregister(migration_probe);

	module_hook_unregister(&kmh_migration_aborted, kmcb_migration_aborted);
	module_hook_unregister(&kmh_migration_end, kmcb_migration_end);
	module_hook_unregister(&kmh_migration_start, kmcb_migration_start);

	scheduler_probe_free(migration_probe);
	for (i = 0; migration_probe_sources[i] != NULL; i++)
		scheduler_probe_source_free(migration_probe_sources[i]);
}

module_init(migration_probe_start);
module_exit(migration_probe_exit);
