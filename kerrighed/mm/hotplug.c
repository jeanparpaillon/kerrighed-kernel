/** Implementation of memory related hotplug mechanisms.
 *  @file hotplug.c
 *
 *  Copyright (C) 2009, Renaud Lottiaux, Kerlabs.
 */

#include <linux/notifier.h>
#include <linux/hashtable.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/pid.h>
#include <kddm/kddm_types.h>
#include "memory_io_linker.h"
#include "mm_struct.h"

static int get_mm_struct_injection_node(struct kddm_set *set,
					objid_t objid,
					struct kddm_obj *obj_entry,
					void *_data)
{
	static kerrighed_node_t dest_node = 0;

	dest_node = krgnode_next_online_in_ring (dest_node);

	return dest_node;
}

static int get_page_injection_node(struct kddm_set *set,
				   objid_t objid,
				   struct kddm_obj *obj_entry,
				   void *_data)
{
	kerrighed_node_t *dest_node = _data;

	return *dest_node;
}

static void do_flush_all_pages (void *_set, void *data)
{
	kerrighed_node_t dest_node;
	struct kddm_set *set = _set;
	struct mm_struct *mm;
	pid_t *pid;

	if (set->iolinker != &memory_linker)
		return;

	pid = set->private_data;

	dest_node = krg_lock_pid_location(*pid);
	if (dest_node == KERRIGHED_NODE_ID_NONE)
		BUG();
	else
		krg_unlock_pid_location(*pid);

	mm = set->obj_set;
	BUG_ON (!mm);

	_kddm_flush_object (mm_struct_kddm_set, mm->mm_id, dest_node);

	_kddm_flush_set(set, get_page_injection_node, &dest_node);
}


static void flush_all_pages(void)
{
	down (&kddm_def_ns->table_sem);
	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 do_flush_all_pages, NULL);
	up (&kddm_def_ns->table_sem);
}

int mm_notification(struct notifier_block *nb, hotplug_event_t event,
		    void *data)
{
	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		flush_all_pages();
		_kddm_flush_set(mm_struct_kddm_set,
				get_mm_struct_injection_node,
				NULL);
		break;

	case HOTPLUG_NOTIFY_REMOVE_ADVERT:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_REMOVE_DISTANT:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_REMOVE_ACK:
		/* Nothing to do */
		break;

	case HOTPLUG_NOTIFY_FAIL:
		/* Not yet managed */
		BUG();

	default:
		BUG();
	}

	return NOTIFY_OK;
}
