/**
 *  Implementation of fs related hotplug mechanisms.
 *  @file hotplug.c
 *
 *  Copyright (C) 2009, Louis Rilling, Kerlabs.
 */

#include <linux/notifier.h>
#include <linux/unique_id.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/file.h>
#include <kddm/kddm.h>

#include "faf/faf_internal.h"

static int dvfs_file_struct_flusher(struct kddm_set *set, objid_t objid,
				    struct kddm_obj *obj_entry, void *data)
{
	kerrighed_node_t orig_node = (objid >> UNIQUE_ID_NODE_SHIFT);
	if (krgnode_online(orig_node))
		return orig_node;
	return nth_online_krgnode(objid % kerrighed_nb_nodes);
}

static int dvfs_remove_local(const krgnodemask_t *nodes)
{
	dvfs_file_remove_local();
	_kddm_flush_set(dvfs_file_struct_ctnr, dvfs_file_struct_flusher, NULL);
	return 0;
}

static int fs_remove_local(struct hotplug_context *ctx)
{
	int err;

	err = faf_remove_local(ctx);
	if (err)
		return err;
	return dvfs_remove_local(&ctx->node_set.v);
}

static int fs_notification(struct notifier_block *nb, hotplug_event_t event,
			   void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch (event) {
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = fs_remove_local(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

void fs_hotplug_init(void)
{
	register_hotplug_notifier(fs_notification, HOTPLUG_PRIO_FS);
}
