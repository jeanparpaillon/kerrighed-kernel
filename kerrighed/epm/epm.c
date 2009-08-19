/*
 *  kerrighed/epm/epm.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <kerrighed/ghost.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgsyms.h>
#include <kerrighed/debug.h>
#include "epm_internal.h"

struct task_struct *baby_sitter;

static void init_baby_sitter(void)
{
	baby_sitter = alloc_task_struct();
	if (!baby_sitter)
		OOM;

	baby_sitter->pid = -1;
	baby_sitter->tgid = baby_sitter->pid;
	baby_sitter->state = TASK_UNINTERRUPTIBLE;
	INIT_LIST_HEAD(&baby_sitter->children);
	baby_sitter->real_parent = baby_sitter;
	baby_sitter->parent = baby_sitter;
	strncpy(baby_sitter->comm, "baby sitter", 15);
}

/* Krgsyms to register for restart_blocks in ghost processes */
extern int compat_krgsyms_register(void);
extern int hrtimer_krgsyms_register(void);
extern int posix_cpu_timers_krgsyms_register(void);
extern int select_krgsyms_register(void);
extern int futex_krgsyms_register(void);
extern int compat_krgsyms_unregister(void);
extern int hrtimer_krgsyms_unregister(void);
extern int posix_cpu_timers_krgsyms_unregister(void);
extern int select_krgsyms_unregister(void);
extern int futex_krgsyms_unregister(void);

static int restart_block_krgsyms_register(void)
{
	int retval;

	retval = krgsyms_register(KRGSYMS_DO_NO_RESTART_SYSCALL,
			do_no_restart_syscall);
#ifdef CONFIG_COMPAT
	if (!retval)
		retval = compat_krgsyms_register();
#endif
	if (!retval)
		retval = hrtimer_krgsyms_register();
	if (!retval)
		retval = posix_cpu_timers_krgsyms_register();
	if (!retval)
		retval = select_krgsyms_register();
	if (!retval)
		retval = futex_krgsyms_register();

	return retval;
}

static int restart_block_krgsyms_unregister(void)
{
	int retval;

	retval = krgsyms_unregister(KRGSYMS_DO_NO_RESTART_SYSCALL);
#ifdef CONFIG_COMPAT
	if (!retval)
		retval = compat_krgsyms_unregister();
#endif
	if (!retval)
		retval = hrtimer_krgsyms_unregister();
	if (!retval)
		retval = posix_cpu_timers_krgsyms_unregister();
	if (!retval)
		retval = select_krgsyms_unregister();
	if (!retval)
		retval = futex_krgsyms_unregister();

	return retval;
}

int init_epm(void)
{
	printk("EPM initialisation: start\n");

	restart_block_krgsyms_register();

	init_baby_sitter();

	epm_signal_start();
	epm_sighand_start();
	epm_children_start();

	epm_pid_start();

	epm_remote_clone_start();
	register_remote_clone_hooks();

	epm_migration_start();

	register_checkpoint_hooks();

	epm_procfs_start();

	application_cr_server_init();

	epm_hotplug_init();

	printk("EPM initialisation: done\n");
	return 0;
}

void cleanup_epm(void)
{
	epm_hotplug_cleanup();
	application_cr_server_finalize();
	epm_procfs_exit();
	epm_migration_exit();
	epm_remote_clone_exit();
	epm_pid_exit();
	epm_children_exit();
	epm_sighand_exit();
	epm_signal_exit();
	restart_block_krgsyms_unregister();
}
