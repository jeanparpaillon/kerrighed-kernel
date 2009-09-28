/*
 *  kerrighed/epm/pidmap.c
 *
 *  Copyright (C) 2009 Louis Rilling - Kerlabs
 */

#include <linux/pid_namespace.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

struct pidmap_map {
	kerrighed_node_t host[KERRIGHED_MAX_NODES];
};

static struct kddm_set *pidmap_map_kddm_set;
static struct pidmap_map pidmap_map;
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

	return err;
}

void pidmap_map_read_unlock(void)
{
	_kddm_put_object(pidmap_map_kddm_set, 0);
}

kerrighed_node_t pidmap_node(kerrighed_node_t node)
{
	return pidmap_map.host[node];
}

struct pid_namespace *node_pidmap(kerrighed_node_t node)
{
	return foreign_pidmap[node];
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
