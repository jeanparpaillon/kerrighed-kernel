/*
 *  kerrighed/epm/epm.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <kerrighed/action.h>
#include <kerrighed/ghost.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krgsyms.h>
#include <kerrighed/debug.h>
#include <kerrighed/pid.h>
#include "epm_internal.h"

struct task_struct *baby_sitter;

static void init_baby_sitter(void)
{
	baby_sitter = alloc_task_struct();
	if (!baby_sitter)
		OOM;

	memset(baby_sitter, 0, sizeof(*baby_sitter));
	baby_sitter->pid = -1;
	baby_sitter->tgid = baby_sitter->pid;
	baby_sitter->state = TASK_UNINTERRUPTIBLE;
	INIT_LIST_HEAD(&baby_sitter->children);
	baby_sitter->real_parent = baby_sitter;
	baby_sitter->parent = baby_sitter;
	strncpy(baby_sitter->comm, "baby sitter", 15);
}

#ifdef CONFIG_DYNAMIC_DEBUG
#define dynamic_pr_kerrighed(fmt, ...) do {				\
	static struct _ddebug descriptor				\
	__used								\
	__attribute__((section("__verbose"), aligned(8))) =		\
	{ KBUILD_MODNAME, __func__, __FILE__, fmt, DEBUG_HASH,	\
		DEBUG_HASH2, __LINE__, _DPRINTK_FLAGS_DEFAULT };	\
	if (__dynamic_dbg_enabled(descriptor))				\
		printk(KERN_DEBUG "kerrighed: " pr_fmt(fmt),		\
				##__VA_ARGS__);				\
	} while (0)
#else
#define dynamic_pr_kerrighed(fmt, ...)  do { } while (0)
#endif

#define pr_kerrighed(fmt, ...) do { \
		dynamic_pr_kerrighed(fmt, ##__VA_ARGS__);	\
	} while (0)

static void __print_low_mem(const char *action, int error)
{
	pr_kerrighed("WARNING: Memory is low. %s: error %d\n",
		     action, error);
}

static void __print_app_error(const char *action, long appid, int error,
			      const char *msg)
{
	pr_kerrighed("%s of application %ld: error %d: %s\n",
		     action, appid, error, msg);
}

void print_app_error(const char *action, long appid, int error,
		     char *fmt, ...)
{
	va_list args;
	char *buffer;

	va_start(args, fmt);
	buffer = kvasprintf(GFP_KERNEL, fmt, args);
	va_end(args);

	if (!buffer) {
		__print_low_mem(action, error);
		return;
	}

	__print_app_error(action, appid, error, buffer);
}

static void __print_pid_error(const char *action, pid_t pid, int error,
			      const char *msg)
{
	pr_kerrighed("%s of %d: error %d: %s\n",
		     action, pid, error, msg);
}

static void __print_task_error(const char *action, pid_t pid, const char *comm,
			       int error, const char *msg)
{
	pr_kerrighed("%s of %d (%s): error %d: %s\n",
		     action, pid, comm, error, msg);
}

static void __print_epm_error(struct epm_action *action, int error,
			      struct task_struct *task, char *fmt,
			      va_list args)
{
	char *buffer;
	buffer = kvasprintf(GFP_KERNEL, fmt, args);

	if (!buffer) {
		__print_low_mem(krg_action_to_str(action), error);
		return;
	}

	if (task && task->pid)
		__print_task_error(krg_action_to_str(action),
				   task_pid_knr(task),
				   task->comm, error, buffer);
	else {
		switch (action->type) {
		case EPM_MIGRATE:
			__print_pid_error(krg_action_to_str(action),
					  action->migrate.pid,
					  error, buffer);
			break;

		case EPM_REMOTE_CLONE:
			__print_pid_error(krg_action_to_str(action),
					  action->remote_clone.from_pid,
					  error, buffer);
			break;

		case EPM_CHECKPOINT:
			__print_app_error(krg_action_to_str(action),
					  action->checkpoint.appid,
					  error, buffer);
			break;

		case EPM_RESTART:
			__print_app_error(krg_action_to_str(action),
					  action->restart.appid,
					  error, buffer);
			break;

		default:
			BUG();
		}
	}

	kfree(buffer);
}

void print_epm_error(struct epm_action *action, int error,
		       struct task_struct *task, char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	__print_epm_error(action, error, task, fmt, args);
	va_end(args);
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

	epm_pidmap_start();
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
	epm_pidmap_exit();
	epm_children_exit();
	epm_sighand_exit();
	epm_signal_exit();
	restart_block_krgsyms_unregister();
}
