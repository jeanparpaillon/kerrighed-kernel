/*
 *  kerrighed/epm/pidmap.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */

#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/rwsem.h>
#include <kerrighed/pid.h>
#include <kerrighed/namespace.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

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
	for_each_online_krgnode(n)
		map->host[n] = n;

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

	set_bit(1, pidmap_ns->pidmap[0].page);
	atomic_dec(&pidmap_ns->pidmap[0].nr_free);

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
}

void epm_pidmap_exit(void)
{
	return;
}
