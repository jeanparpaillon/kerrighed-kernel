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

static void do_flush_all_pages(struct kddm_set *set)
{
	kerrighed_node_t dest_node;
	struct anon_vma_kddm_set_private *private;
	struct mm_struct *mm, *obj_mm;
	objid_t mm_id;
	pid_t pid;

	mm = set->obj_set;
	BUG_ON (!mm);

	private = set->private_data;

	pid = private->last_pid;
	dest_node = krg_lock_pid_location(pid);
	if (dest_node == KERRIGHED_NODE_ID_NONE) {
		pid = private->last_tgid;
		dest_node = krg_lock_pid_location(pid);
	}
	if (dest_node != KERRIGHED_NODE_ID_NONE) {
		krg_unlock_pid_location(pid);
	} else {
		dest_node = set->def_owner;
		if (!krgnode_online(dest_node))
			dest_node = nth_online_krgnode(dest_node % num_online_krgnodes());
	}
	BUG_ON(!krgnode_online(dest_node));

	mm_id = mm->mm_id;
	if (!mm_id)
		return;

	/*
	 * To avoid racing with the destruction of this set in kcb_mm_release(),
	 * set is flushed with mm_struct grabbed.
	 */
	obj_mm = _kddm_grab_object_no_ft(mm_struct_kddm_set, mm_id);
	if (!obj_mm) {
		_kddm_put_object(mm_struct_kddm_set, mm_id);
		return;
	}
	BUG_ON(obj_mm != mm);

	krgnode_clear(kerrighed_node_id, mm->copyset);

	_kddm_flush_set(set, get_page_injection_node, &dest_node);

	_kddm_put_object(mm_struct_kddm_set, mm_id);

	_kddm_flush_object (mm_struct_kddm_set, mm_id, dest_node);
}

struct memory_set_list {
	struct memory_set_list *next;
	struct kddm_set *set;
};

static void list_memory_sets(void *_set, void *_head)
{
	struct kddm_set *set = _set;
	struct memory_set_list **head = _head;
	struct memory_set_list *list;

	if (set->iolinker != &memory_linker)
		return;

	list = kmalloc(sizeof(*list), GFP_KERNEL);
	if (!list)
		OOM;

	atomic_inc(&set->count);
	list->set = set;
	list->next = *head;
	*head = list;
}

static void flush_all_pages(void)
{
	struct memory_set_list *head = NULL;
	struct memory_set_list *next;

	down_read(&kddm_def_ns->table_sem);
	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 list_memory_sets, &head);
	up_read(&kddm_def_ns->table_sem);

	while (head) {
		do_flush_all_pages(head->set);
		put_kddm_set(head->set);

		next = head->next;
		kfree(head);
		head = next;
	}
}

static void do_destroy_kddm (void *_set, void *data)
{
	struct kddm_set *set = _set;

	if (set->iolinker != &memory_linker)
		return;

	_destroy_kddm_set (set);
}

static void destroy_all_kddms(void)
{
	__hashtable_foreach_data(kddm_def_ns->kddm_set_table,
				 do_destroy_kddm, NULL);
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
		destroy_all_kddms();
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
