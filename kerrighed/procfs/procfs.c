/** Initialization of procfs stuffs for ProcFS module.
 *  @file procfs.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include "proc.h"
#ifdef CONFIG_KRG_PROC
#include "proc_pid.h"
#endif
#include "static_node_info_linker.h"
#include "static_cpu_info_linker.h"
#include <kerrighed/dynamic_node_info_linker.h>
#include "dynamic_cpu_info_linker.h"

int procfs_hotplug_init(void);
void procfs_hotplug_cleanup(void);

int init_procfs(void)
{
	static_node_info_init();
	static_cpu_info_init();
	dynamic_node_info_init();
	dynamic_cpu_info_init();

#ifdef CONFIG_KRG_PROC
	proc_pid_init();
#endif

	krg_procfs_init();

	procfs_hotplug_init();

	return 0;
}

void cleanup_procfs(void)
{
	procfs_hotplug_cleanup();
	krg_procfs_finalize();

#ifdef CONFIG_KRG_PROC
	proc_pid_finalize();
#endif
}
