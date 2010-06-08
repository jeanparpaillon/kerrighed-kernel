/**
 *  Implementation of faf related hotplug mechanisms.
 *  @file hotplug.c
 *
 *  Copyright (C) 2009, Louis Rilling, Kerlabs.
 */

#include <linux/remote_sleep.h>
#include <linux/list.h>
#include <linux/rwsem.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krginit.h>
#include <kerrighed/krgnodemask.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>

#include "faf_internal.h"

struct list_head client_list[KERRIGHED_MAX_NODES];
struct rw_semaphore client_list_sem[KERRIGHED_MAX_NODES];
DECLARE_RWSEM(faf_srv_hotplug_rwsem);

bool faf_srv_hold(struct faf_client_data *data)
{
	bool ret;

	if (data->server_dead)
		return false;

	down_read(&client_list_sem[data->server_id]);
	ret = !data->server_dead;
	if (!ret)
		up_read(&client_list_sem[data->server_id]);

	return ret;
}

void faf_srv_release(struct faf_client_data *data)
{
	up_read(&client_list_sem[data->server_id]);
}

static int handle_faf_invalidate(struct rpc_desc *desc,
				 void *_msg,
				 size_t size)
{
	kerrighed_node_t node = *(kerrighed_node_t *)_msg;
	struct faf_client_data *data, *safe;

	down_write(&client_list_sem[node]);
	list_for_each_entry_safe(data, safe, &client_list[node], list) {
		list_del(&data->list);
		/*
		 * Matches smp_read_barrier_depends() in
		 * faf.c:free_faf_file_private_data()
		 */
		smp_wmb();
		data->server_dead = 1;
	}
	up_write(&client_list_sem[node]);

	return 0;
}

int faf_remove_local(const krgnodemask_t *nodes)
{
	krgnodemask_t to_invalidate;
	int err;

	remote_sleepers_cancel(&faf_remote_sleepers);

	krgnodes_or(to_invalidate, krgnode_online_map, *nodes);
	krgnode_clear(kerrighed_node_id, to_invalidate);
	err = rpc_sync_m(RPC_FAF_INVALIDATE, &to_invalidate,
			 &kerrighed_node_id, sizeof(kerrighed_node_id));
	if (err)
		return err;

	down_write(&faf_srv_hotplug_rwsem);
	check_close_faf_srv_files();
	faf_polled_fd_remove_local();
	up_write(&faf_srv_hotplug_rwsem);

	remote_sleepers_enable(&faf_remote_sleepers);

	return err;
}

void faf_hotplug_init(void)
{
	kerrighed_node_t n;

	for (n = 0; n < KERRIGHED_MAX_NODES; n++) {
		INIT_LIST_HEAD(&client_list[n]);
		init_rwsem(&client_list_sem[n]);
	}

	rpc_register_int(RPC_FAF_INVALIDATE, handle_faf_invalidate, 0);
}
