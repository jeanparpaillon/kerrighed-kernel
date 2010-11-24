/** Unique id generator
 *  @file unique_id.c
 *
 *  Implementation of unique id generator. This mechanism generates
 *  locally, an indentifier which is unique in the cluster.
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/hardirq.h>
#include <linux/module.h>
#include <linux/unique_id.h>
#include <kerrighed/krginit.h>
#ifdef CONFIG_KRG_HOTPLUG
#include <linux/cluster_barrier.h>
#include <kerrighed/hotplug.h>
#include <kddm/kddm.h>
#endif

#define INITVAL 1

#ifdef CONFIG_KRG_HOTPLUG
struct kddm_set *unique_id_set;
struct cluster_barrier *unique_id_barrier;

static struct unique_id_root *roots[NR_UNIQUE_IDS];
#endif

unique_id_root_t mm_unique_id_root = {
	.local_unique_id = ATOMIC_LONG_INIT(INITVAL),
};

#ifdef CONFIG_KRG_HOTPLUG
static void register_root(enum unique_id_type type, struct unique_id_root *root)
{
	BUG_ON(type < 0 && type >= NR_UNIQUE_IDS);
	BUG_ON(roots[type]);
	roots[type] = root;
}

void unregister_unique_id_root(enum unique_id_type type)
{
	BUG_ON(!roots[type]);
	roots[type] = NULL;
}
#else
static
inline
void register_root(enum unique_id_type type, struct unique_id_root *root)
{
}
#endif

/** Initialize a unique id root.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root to initialize
 *  @return       0 if everything ok.
 *                Negative value otherwise.
 */
int init_unique_id_root(enum unique_id_type type, unique_id_root_t *root)
{
	/* Value 0 is reserved for UNIQUE_ID_NONE */

	atomic_long_set (&root->local_unique_id, INITVAL);
	register_root(type, root);

	return 0;
}
EXPORT_SYMBOL(init_unique_id_root);



/** Initialize a unique id root with a given init value.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root to initialize
 *  @param base   Init of value for the key generator.
 *  @return       0 if everything ok.
 *                Negative value otherwise.
 */
int init_and_set_unique_id_root(enum unique_id_type type,
				unique_id_root_t *root, int base)
{
	atomic_long_set (&root->local_unique_id, base + INITVAL);
	register_root(type, root);

	return 0;
}
EXPORT_SYMBOL(init_and_set_unique_id_root);



/** Generate a unique id from a given root.
 *  @author Renaud Lottiaux
 *
 *  @param root   The root of the unique id to generate.
 *  @return       A unique id !
 */
unique_id_t get_unique_id(unique_id_root_t *root)
{
	unique_id_t unique_id ;

	/* If the unique ID root has not been initialized... */
	if (atomic_long_read(&root->local_unique_id) == 0)
		return UNIQUE_ID_NONE;

	unique_id = atomic_long_inc_return (&root->local_unique_id);

	/* Check if there is a loop in the identitier generator */

	if ((unique_id & UNIQUE_ID_LOCAL_MASK) == 0)
		panic ("Unique id generator loop !\n");

	/* Combine local unique id and local node id to generate a
	   identifier which is unique cluster wide */

	unique_id = unique_id | ((unsigned long)kerrighed_node_id << UNIQUE_ID_NODE_SHIFT);

	return unique_id;
}
EXPORT_SYMBOL(get_unique_id);


void init_unique_ids(void)
{
	init_unique_id_root(UNIQUE_ID_MM, &mm_unique_id_root);
}


#ifdef CONFIG_KRG_HOTPLUG
static
kerrighed_node_t unique_ids_default_owner(struct kddm_set *set, objid_t objid,
					  const krgnodemask_t *nodes,
					  int nr_nodes)
{
	if (__krgnode_isset(objid, nodes))
		return objid;
	else
		return __next_krgnode_in_ring(objid, nodes);
}

static struct iolinker_struct unique_id_io_linker = {
	.linker_name   = "unique_id ",
	.linker_id     = UNIQUE_ID_LINKER,
	.default_owner = unique_ids_default_owner,
};

static int recover_unique_ids(void)
{
	struct unique_id_root *ids;
	int i;

	ids = _kddm_get_object_no_ft(unique_id_set, kerrighed_node_id);
	if (IS_ERR(ids))
		return PTR_ERR(ids);

	if (ids)
		for (i = 0; i < NR_UNIQUE_IDS; i++)
			atomic_long_set(&roots[i]->local_unique_id,
					atomic_long_read(&ids[i].local_unique_id));

	_kddm_put_object(unique_id_set, kerrighed_node_id);
	return 0;
}

static int unique_ids_add(struct hotplug_context *ctx)
{
	krgnodemask_t nodes;
	int  err;

	if (krgnode_isset(kerrighed_node_id, ctx->node_set.v)) {
		err = recover_unique_ids();
		if (err)
			return err;
	}

	krgnodes_or(nodes, krgnode_online_map, ctx->node_set.v);
	err = cluster_barrier(unique_id_barrier, &nodes, first_krgnode(nodes));
	if (err)
		return err;
	return cluster_barrier(unique_id_barrier, &nodes, first_krgnode(nodes));
}

static int unique_id_flusher(struct kddm_set *set, objid_t id,
			     struct kddm_obj *obj, void *data)
{
	return nth_online_krgnode(id % num_online_krgnodes());
}

static int unique_ids_remove_local(struct hotplug_context *ctx)
{
	kerrighed_node_t node;
	struct unique_id_root *ids;
	int i;

	if (!num_online_krgnodes()) {
		for (node = 0; node < KERRIGHED_MAX_NODES; node++)
			_kddm_remove_object(unique_id_set, node);
		return 0;
	}

	ids = _kddm_grab_object(unique_id_set, kerrighed_node_id);
	if (IS_ERR(ids))
		return PTR_ERR(ids);
	BUG_ON(!ids);
	for (i = 0; i < NR_UNIQUE_IDS; i++)
		atomic_long_set(&ids[i].local_unique_id,
				atomic_long_read(&roots[i]->local_unique_id));
	_kddm_put_object(unique_id_set, kerrighed_node_id);

	_kddm_flush_set(unique_id_set, unique_id_flusher, NULL);

	return 0;
}

static int hotplug_notifier(struct notifier_block *nb, hotplug_event_t event,
			    void *data)
{
	struct hotplug_context *ctx = data;
	int err;

	switch(event){
	case HOTPLUG_NOTIFY_ADD:
		err = unique_ids_add(ctx);
		break;
	case HOTPLUG_NOTIFY_REMOVE_LOCAL:
		err = unique_ids_remove_local(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int init_unique_ids_hotplug(void)
{
	register_io_linker(UNIQUE_ID_LINKER, &unique_id_io_linker);
	unique_id_set = create_new_kddm_set(kddm_def_ns, UNIQUE_ID_KDDM_ID,
					    UNIQUE_ID_LINKER,
					    KDDM_CUSTOM_DEF_OWNER,
					    NR_UNIQUE_IDS * sizeof(struct unique_id_root),
					    0);
	if (IS_ERR(unique_id_set))
		panic("kerrighed: Couldn't create unique_ids_set!\n");

	unique_id_barrier = alloc_cluster_barrier(UNIQUE_ID_HOTPLUG_BARRIER);
	if (IS_ERR(unique_id_barrier))
		panic("kerrighed: Couldn't create unique_id_barrier!\n");

	register_hotplug_notifier(hotplug_notifier, HOTPLUG_PRIO_UNIQUE_ID);

	return 0;
}

void cleanup_unique_ids_hotplug(void)
{
}
#endif
