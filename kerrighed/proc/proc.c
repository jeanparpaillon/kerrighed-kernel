/*
 *  kerrighed/proc/proc.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 *  Copyright (C) 2006-2007 Pascal Gallard - Kerlabs, Louis Rilling - Kerlabs
 */

#include <linux/kernel.h>

#include "proc_internal.h"

/** Initial function of the module
 *  @author Geoffroy Vallee, Pascal Gallard
 */
int init_proc(void)
{
	printk("Proc initialisation: start\n");

	proc_task_start();
	proc_krg_exit_start();

	proc_remote_syscalls_start();
	register_remote_syscalls_hooks();

	printk("Proc initialisation: done\n");

	return 0;
}

void cleanup_proc(void)
{
}
