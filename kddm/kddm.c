/** KDDM module initialization.
 *  @file kddm.c
 *
 *  Implementation of functions used to initialize and finalize the
 *  KDDM module. It also implements some device file system functions for
 *  testing purpose.
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <kerrighed/hotplug.h>
#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "procfs.h"
#include "protocol_action.h"
#include <kddm/name_space.h>
#include <kddm/kddm_set.h>
#include "kddm_bench.h"

#ifndef CONFIG_KRG_MONOLITHIC
MODULE_AUTHOR ("Renaud Lottiaux");
MODULE_DESCRIPTION ("Kerrighed Distributed Data Manager");
MODULE_LICENSE ("GPL");
#endif

event_counter_t total_get_object_counter = 0;
event_counter_t total_grab_object_counter = 0;
event_counter_t total_remove_object_counter = 0;
event_counter_t total_flush_object_counter = 0;

int (*kh_copy_kddm_info)(unsigned long clone_flags, struct task_struct * tsk);

struct kmem_cache *kddm_info_cachep;

int kddm_hotplug_init(void);
void kddm_hotplug_cleanup(void);


/** Initialize the kddm field of the krg_task field of the given task.
 *  @author  Renaud Lottiaux
 *
 *  @param tsk   Task to fill the kddm struct.
 */
int initialize_kddm_info_struct (struct task_struct *task)
{
	struct kddm_info_struct *kddm_info;

	kddm_info = kmem_cache_alloc (kddm_info_cachep, GFP_KERNEL);
	if (!kddm_info)
		return -ENOMEM;

	kddm_info->get_object_counter = 0;
	kddm_info->grab_object_counter = 0;
	kddm_info->remove_object_counter = 0;
	kddm_info->flush_object_counter = 0;
	kddm_info->wait_obj = NULL;

	task->kddm_info = kddm_info;

	return 0;
}



int kcb_copy_kddm_info(unsigned long clone_flags, struct task_struct * tsk)
{
	return initialize_kddm_info_struct(tsk);
}



/** Initialisation of the KDDM sub-system module.
 *  @author Renaud Lottiaux
 */
int init_kddm (void)
{
	printk ("KDDM initialisation : start\n");

        kddm_info_cachep = KMEM_CACHE(kddm_info_struct, SLAB_PANIC);

	kddm_ns_init();

	io_linker_init();

	kddm_set_init();

	init_kddm_objects();

	procfs_kddm_init ();

	object_server_init ();

	start_run_queue_thread ();

	hook_register(&kh_copy_kddm_info, kcb_copy_kddm_info);

	kddm_hotplug_init();

	init_kddm_test ();

	/*
	  process_add(0, kerrighed_nb_nodes);
	  process_synchronize(0);
	  process_remove(0);
	*/

	krgsyms_register (KRGSYMS_KDDM_TREE_OPS, &kddm_tree_set_ops);

	printk ("KDDM initialisation done\n");

	return 0;
}



/** Cleanup of the KDDM sub-system.
 *  @author Renaud Lottiaux
 */
void cleanup_kddm (void)
{
	printk ("KDDM termination : start\n");

	krgsyms_unregister (KRGSYMS_KDDM_TREE_OPS);

	kddm_hotplug_cleanup();

	stop_run_queue_thread ();

	procfs_kddm_finalize ();

	object_server_finalize ();

	kddm_set_finalize();

	io_linker_finalize();

	kddm_ns_finalize();

	printk ("KDDM termination done\n");
}
