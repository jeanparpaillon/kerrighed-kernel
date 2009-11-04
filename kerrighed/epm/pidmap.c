/*
 *  kerrighed/epm/pidmap.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */

#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/rwsem.h>
#include <kerrighed/pid.h>
#include <kerrighed/namespace.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>
#include <kddm/kddm.h>

#include "pid.h"

#define BITS_PER_PAGE (PAGE_SIZE * 8)

struct pidmap_map {
	kerrighed_node_t host[KERRIGHED_MAX_NODES];
};

static struct kddm_set *pidmap_map_kddm_set;
static struct pidmap_map pidmap_map;
static DECLARE_RWSEM(pidmap_map_rwsem);
static struct pid_namespace *foreign_pidmap[KERRIGHED_MAX_NODES];

static int pidmap_map_alloc_object(struct kddm_obj *obj_entry,
				   struct kddm_set *set, objid_t objid)
{
	BUG_ON(objid);
	obj_entry->object = &pidmap_map;
	return 0;
}

static int pidmap_map_first_touch(struct kddm_obj *obj_entry,
				  struct kddm_set *set, objid_t objid,
				  int flags)
{
	struct pidmap_map *map;
	kerrighed_node_t n;
	int err;

	err = pidmap_map_alloc_object(obj_entry, set, objid);
	if (err)
		goto out;

	map = obj_entry->object;
	for (n = 0; n < KERRIGHED_MAX_NODES; n++)
		map->host[n] = KERRIGHED_NODE_ID_NONE;

out:
	return 0;
}

static int pidmap_map_import_object(struct kddm_obj *obj_entry,
				    struct rpc_desc *desc)
{
	struct pidmap_map *map = obj_entry->object;

	return rpc_unpack_type(desc, map->host);
}

static int pidmap_map_export_object(struct rpc_desc *desc,
				    struct kddm_obj *obj_entry)
{
	struct pidmap_map *map = obj_entry->object;

	return rpc_pack_type(desc, map->host);
}

static int pidmap_map_remove_object(void *object,
				    struct kddm_set *set, objid_t objid)
{
	return 0;
}

static struct iolinker_struct pidmap_map_io_linker = {
	.first_touch   = pidmap_map_first_touch,
	.linker_name   = "pidmap_map",
	.linker_id     = PIDMAP_MAP_LINKER,
	.alloc_object  = pidmap_map_alloc_object,
	.export_object = pidmap_map_export_object,
	.import_object = pidmap_map_import_object,
	.remove_object = pidmap_map_remove_object,
};

int pidmap_map_read_lock(void)
{
	struct pidmap_map *map;
	int err = 0;

	map = _kddm_get_object(pidmap_map_kddm_set, 0);
	BUG_ON(!map);
	if (IS_ERR(map))
		err = PTR_ERR(map);
	else
		down_read(&pidmap_map_rwsem);

	return err;
}

void pidmap_map_read_unlock(void)
{
	up_read(&pidmap_map_rwsem);
	_kddm_put_object(pidmap_map_kddm_set, 0);
}

int pidmap_map_write_lock(void)
{
	struct pidmap_map *map;
	int err = 0;

	map = _kddm_grab_object(pidmap_map_kddm_set, 0);
	BUG_ON(!map);
	if (IS_ERR(map))
		err = PTR_ERR(map);
	else
		down_write(&pidmap_map_rwsem);

	return err;
}

void pidmap_map_write_unlock(void)
{
	up_write(&pidmap_map_rwsem);
	_kddm_put_object(pidmap_map_kddm_set, 0);
}

static struct pid_namespace *pidmap_alloc(void)
{
	struct pid_namespace *pidmap_ns;

	pidmap_ns = create_pid_namespace(0);
	if (IS_ERR(pidmap_ns))
		return pidmap_ns;

	set_bit(1, pidmap_ns.pidmap[0].page);
	atomic_dec(&pidmap_ns.pidmap[0].nr_free);

	return pidmap_ns;
}

int pidmap_map_alloc(kerrighed_node_t node)
{
	struct pid_namespace *pidmap_ns;
	int err;

	err = pidmap_map_write_lock();
	if (err)
		goto out;

	if (pidmap_map.host[node] != KERRIGHED_NODE_ID_NONE)
		goto unlock;

	/*
	 * Stupid policy: allocate here. We could do some load balancing if
	 * required.
	 */
	pidmap_ns = pidmap_alloc();
	if (IS_ERR(pidmap_ns)) {
		err = PTR_ERR(pidmap_ns);
		goto unlock;
	}

	foreign_pidmap[node] = pidmap_ns;
	pidmap_map.host[node] = kerrighed_node_id;

unlock:
	pidmap_map_write_unlock();

out:
	return err;
}

kerrighed_node_t pidmap_node(kerrighed_node_t node)
{
	return pidmap_map.host[node];
}

struct pid_namespace *node_pidmap(kerrighed_node_t node)
{
	return foreign_pidmap[node];
}

void krg_free_pidmap(struct upid *upid)
{
	struct pid_namespace *pidmap_ns = node_pidmap(ORIG_NODE(upid->nr));
	struct upid __upid = {
		.nr = upid->nr,
		.ns = pidmap_ns,
	};

	if (pidmap_ns)
		__free_pidmap(&__upid);
}

void pidmap_map_cleanup(struct krg_namespace *krg_ns)
{
	kerrighed_node_t node;
	struct pid_namespace *ns;

	BUG_ON(num_online_krgnodes());

	/*
	 * Wait until all PIDs are ready to be reused
	 * Restarted processes may have created pid kddm objects which logic
	 * delays the actual free of the pidmap entry after the last user is
	 * reaped.
	 */
	pid_wait_quiescent();

	_kddm_remove_object(pidmap_map_kddm_set, 0);

	for (node = 0; node < KERRIGHED_MAX_NODES; node++) {
		ns = foreign_pidmap[node];
		if (ns) {
			BUG_ON(next_pidmap(ns, 1) >= 0);
			put_pid_ns(ns);
			foreign_pidmap[node] = NULL;
		}
	}
}

static int recv_pidmap(struct rpc_desc *desc,
		       kerrighed_node_t node,
		       struct pid_namespace *pidmap_ns)
{
	void *page;
	struct pidmap *map;
	int i, nr_pages, page_index;
	int nr_free ;
	int err;

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	err = rpc_unpack_type(desc, nr_pages);
	if (err)
		goto err;
	if (!nr_pages)
		goto freepage;

	for (i = 0; i < nr_pages; i++) {
		err = rpc_unpack_type(desc, page_index);
		if (err)
			goto err;
		map = &pidmap_ns->pidmap[page_index];
		if (!map->page) {
			err = alloc_pidmap_page(map);
			if (err)
				goto err;
		}
		err = rpc_unpack(desc, 0, page, PAGE_SIZE);
		if (err)
			goto err;
		err = rpc_unpack_type(desc, nr_free);
		if (err)
			goto err;
		if (page_index == 0) {
			int j;

			/*
			 * Init's bit must be set, but might have just been
			 * cleared if the node is being removed. So fix the
			 * incoming map, and recompute nr_free.
			 */
			BUG_ON(!test_bit(1, map->page));
			BUG_ON(atomic_read(&map->nr_free) != BITS_PER_PAGE - 2);

			BUG_ON(!test_bit(0, page));
			set_bit(1, page);
			nr_free = BITS_PER_PAGE - 2;
			for (j = 2; j < BITS_PER_PAGE; j++)
				if (test_bit(j, page))
					nr_free--;
		} else {
			BUG_ON(atomic_read(&map->nr_free) != BITS_PER_PAGE);
		}
		memcpy(map->page, page, PAGE_SIZE);
		atomic_set(&map->nr_free, nr_free);
	}

	i = 1;
	while ((i = next_pidmap(ns, i)) > 0) {
		err = __krg_pid_link_task(GLOBAL_PID_NODE(i, node));
		if (err)
			goto err;
	}

	err = rpc_pack_type(desc, err);
	if (err)
		goto err;

freepage:
	free_page((unsigned long)page);

	return err;

err:
	if (err > 0)
		err = -EPIPE;
	i = 1;
	while ((i = next_pidmap(pidmap_ns, i)) > 0) {
		struct upid upid = {
			.nr = i,
			.ns = pidmap_ns
		};
		__free_pidmap(&upid);
	}
	goto freepage;
}

static int send_pidmap(struct rpc_desc *desc, struct pid_namespace *pidmap_ns)
{
	struct pidmap *map;
	int i, nr_pages;
	int nr_free;
	int err;

	nr_pages = 0;
	if (!pidmap_ns)
		goto send_nr_pages;

	for (i = 0; i < PIDMAP_ENTRIES; i++)
		if (atomic_read(&pidmap_ns->pidmap[i].nr_free) < BITS_PER_PAGE)
			nr_pages++;

send_nr_pages:
	err = rpc_pack_type(desc, nr_pages);
	if (err)
		goto out;

	if (!nr_pages)
		goto out;

	for (i = 0; i < PIDMAP_ENTRIES; i++) {
		map = &pidmap_ns->pidmap[i];
		nr_free = atomic_read(&map->nr_free);
		if (nr_free == BITS_PER_PAGE)
			continue;

		err = rpc_pack_type(desc, i);
		if (err)
			goto out;
		err = rpc_pack(desc, 0, map->page, PAGE_SIZE);
		if (err)
			goto out;
		err = rpc_pack_type(desc, nr_free);
		if (err)
			goto out;
	}

	/* Make sure that the transfer went fine */
	err = rpc_unpack_type(desc, err);
	if (err > 0)
		err = -EPIPE;

out:
	return err;
}

static void handle_pidmap_steal(struct rpc_desc *desc, void *_msg, size_t size)
{
	kerrighed_node_t node = *(kerrighed_node_t *)_msg;
	struct pid_namespace *pidmap_ns = foreign_pidmap[node];

	if (send_pidmap(pidmap_ns)) {
		rpc_cancel(desc);
		return;
	}

	foreign_pidmap[node] = NULL;
	put_pid_ns(pidmap_ns);
}

int pidmap_map_add(struct hotplug_context *ctx)
{
	struct pid_namespace *ns = ctx->ns->root_pid_ns;
	kerrighed_node_t host_node;
	struct rpc_desc *desc;
	int err;

	if (!krgnode_isset(kerrighed_node_id, ctx->node_set.v))
		return 0;

	err = pidmap_map_read_lock();
	if (err)
		return err;
	host_node = pidmap_node(kerrighed_node_id);
	pidmap_map_read_unlock();

	if (host_node == kerrighed_node_id)
		return 0;

	err = pidmap_map_write_lock();
	if (err)
		return err;

	host_node = pidmap_node(kerrighed_node_id);
	if (host_node == KERRIGHED_NODE_ID_NONE) {
		pidmap_map.host[kerrighed_node_id] = kerrighed_node_id;
		goto unlock;
	}
	BUG_ON(host_node == kerrighed_node_id);

	err = -ENOMEM;
	desc = rpc_begin(EPM_PIDMAP_STEAL, host_node);
	if (!desc)
		goto unlock;

	err = rpc_pack_type(desc, kerrighed_node_id);
	if (err)
		goto cancel;

	err = recv_pidmap(desc, kerrighed_node_id, ns);
	if (err)
		goto cancel;

	pidmap_map.host[kerrighed_node_id] = kerrighed_node_id;

end:
	rpc_end(desc, 0);

unlock:
	pidmap_map_write_unlock();

	return err;

cancel:
	rpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	goto end;
}

static void handle_pidmap_inject(struct rpc_desc *desc, void *_msg, size_t size)
{
	kerrighed_node_t node = *(kerrighed_node_t *)_msg;
	struct pid_namespace *pidmap_ns;
	int err;

	pidmap_ns = pidmap_alloc();
	if (IS_ERR(pidmap_ns))
		goto cancel;

	err = recv_pidmap(desc, pidmap_ns);
	if (err) {
		put_pid_ns(pidmap_ns);
		goto cancel;
	}

	foreign_pidmap[node] = pidmap_ns;

	return;

cancel:
	rpc_cancel(desc);
}

static int pidmap_inject(kerrighed_node_t node, struct pid_namespace *pidmap_ns,
			 kerrighed_node_t target)
{
	struct rpc_desc *desc;
	int err;

	desc = rpc_begin(EPM_PIDMAP_INJECT, target);
	if (!desc)
		return -ENOMEM;

	err = rpc_pack_type(desc, node);
	if (err)
		goto cancel;

	err = send_pidmap(desc, pidmap_ns);
	if (err)
		goto cancel;

end:
	rpc_end(desc, 0);
	return err;

cancel:
	rpc_cancel(desc);
	goto end;
}

static int pidmaps_inject(struct hotplug_context *ctx)
{
	kerrighed_node_t target, node;

	target = kerrighed_node_id;
	for (node = 0; node < KERRIGHED_MAX_NODES; node++) {
		if (pidmap_map.host[node] != kerrighed_node_id)
			continue;

		pidmap_ns = foreign_pidmap[node];
		target = krgnode_next_online_in_ring(target);
		err = pidmap_inject(node, pidmap_ns, target);
		if (err)
			return err;

		foreign_pidmap[node] = NULL;
		put_pid_ns(pidmap_ns);

		pidmap_map.host[node] = target;
	}

	target = krgnode_next_online_in_ring(target);
	err = pidmap_inject(kerrighed_node_id, ctx->ns->root_pid_ns, target);
	if (err)
		return err;

	pidmap_map.host[kerrighed_node_id] = target;

	return 0;
}

int pidmap_map_remove_local(struct hotplug_context *ctx)
{
	int err;

	if (!num_online_krgnodes()) {
		pidmap_map_cleanup(ctx->ns);
		return 0;
	}

	pid_wait_quiescent();

	err = pidmap_map_write_lock();
	if (err)
		return err;
	err = pidmaps_inject(ctx);
	pidmap_map_write_unlock();

	return err;
}

void epm_pidmap_start(void)
{
	register_io_linker(PIDMAP_MAP_LINKER, &pidmap_map_io_linker);
	pidmap_map_kddm_set = create_new_kddm_set(kddm_def_ns,
						  PIDMAP_MAP_KDDM_ID,
						  PIDMAP_MAP_LINKER,
						  KDDM_RR_DEF_OWNER,
						  0, 0);
	if (IS_ERR(pidmap_map_kddm_set))
		OOM;

	rpc_register_void(EPM_PIDMAP_STEAL, handle_pidmap_steal, 0);
	rpc_register_void(EPM_PIDMAP_INJECT, handle_pidmap_inject, 0);
}

void epm_pidmap_exit(void)
{
	return;
}
