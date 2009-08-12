/** Common code for IPC mechanism accross the cluster
 *  @file ipc_handler.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#ifndef NO_IPC

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <kddm/kddm.h>

#include "ipcmap_io_linker.h"
#include "ipc_handler.h"
#include "util.h"
#include "krgmsg.h"

/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/

static int kcb_ipc_get_maxid(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map;
	int max_id;

	ipc_map = _kddm_get_object(ids->krgops->map_kddm_set, 0);
	max_id = ipc_map->alloc_map - 1;
	_kddm_put_object(ids->krgops->map_kddm_set, 0);

	return max_id;
}

static int kcb_ipc_get_new_id(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i = 1, id = -1, offset;

	max_id = _kddm_grab_object(ids->krgops->map_kddm_set, 0);

	while (id == -1) {
		ipc_map = _kddm_grab_object(ids->krgops->map_kddm_set, i);

		if (ipc_map->alloc_map != ULONG_MAX) {
			offset = find_first_zero_bit(&ipc_map->alloc_map,
						     BITS_PER_LONG);

			if (offset < BITS_PER_LONG) {

				id = (i-1) * BITS_PER_LONG + offset;
				set_bit(offset, &ipc_map->alloc_map);
				if (id >= max_id->alloc_map)
					max_id->alloc_map = id + 1;
			}
		}

		_kddm_put_object(ids->krgops->map_kddm_set, i);
		i++;
	}

	_kddm_put_object(ids->krgops->map_kddm_set, 0);

	return id;
}

static int kcb_ipc_rmid(struct ipc_ids* ids, int index)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i, offset;

	/* Clear the corresponding entry in the bit field */

	i = 1 + index / BITS_PER_LONG;
	offset = index % BITS_PER_LONG;

	ipc_map = _kddm_grab_object(ids->krgops->map_kddm_set, i);

	BUG_ON(!test_bit(offset, &ipc_map->alloc_map));

	clear_bit(offset, &ipc_map->alloc_map);

	_kddm_put_object(ids->krgops->map_kddm_set, i);

	/* Check if max_id must be adjusted */

	max_id = _kddm_grab_object(ids->krgops->map_kddm_set, 0);

	if (max_id->alloc_map != index + 1)
		goto done;

	for (; i > 0; i--) {

		ipc_map = _kddm_grab_object(ids->krgops->map_kddm_set, i);
		if (ipc_map->alloc_map != 0) {
			for (; offset >= 0; offset--) {
				if (test_bit (offset, &ipc_map->alloc_map)) {
					max_id->alloc_map = 1 + offset +
						(i - 1) * BITS_PER_LONG;
					_kddm_put_object(
						ids->krgops->map_kddm_set, i);
					goto done;
				}
			}
		}
		offset = 31;
		_kddm_put_object(ids->krgops->map_kddm_set, i);
	}

	max_id->alloc_map = 0;
done:
	_kddm_put_object(ids->krgops->map_kddm_set, 0);

	return 0;
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

extern void hook_register(void *hk, void *f);

extern int (*kh_ipc_get_maxid)(struct ipc_ids* ids);
extern int (*kh_ipc_get_new_id)(struct ipc_ids* ids);
extern void (*kh_ipc_rmid)(struct ipc_ids* ids, int index);

void ipc_handler_init(void)
{
	hook_register(&kh_ipc_get_maxid, kcb_ipc_get_maxid);
	hook_register(&kh_ipc_get_new_id, kcb_ipc_get_new_id);
	hook_register(&kh_ipc_rmid, kcb_ipc_rmid);
}

void ipc_handler_finalize(void)
{
}

#endif
