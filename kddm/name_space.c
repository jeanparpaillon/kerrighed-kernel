/** KDDM name space interface.
 *  @file name_space.c
 *
 *  Implementation of KDDM name space manipulation functions.
 *
 *  Copyright (C) 2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/hashtable.h>
#include <linux/module.h>

#include <kddm/kddm.h>
#include <kddm/name_space.h>

struct kddm_ns *kddm_def_ns;
EXPORT_SYMBOL(kddm_def_ns);

struct radix_tree_root kddm_ns_tree;
static DEFINE_RWLOCK(ns_tree_lock);
struct kmem_cache *kddm_ns_cachep;



static inline void free_kddm_ns_entry(struct kddm_ns *ns)
{
	{   /// JUST FOR DEBUGGING: BEGIN
		struct kddm_ns *_ns;

		read_lock_irq(&ns_tree_lock);
		_ns = radix_tree_lookup(&kddm_ns_tree, ns->id);
		read_unlock_irq(&ns_tree_lock);

		BUG_ON (_ns != NULL);
	}   /// JUST FOR DEBUGGING: END

	hashtable_free(ns->kddm_set_table);
	kmem_cache_free(kddm_ns_cachep, ns);
}



void kddm_ns_put(struct kddm_ns *ns)
{
	if (atomic_dec_and_test(&ns->count))
		free_kddm_ns_entry(ns);
}



struct kddm_ns * create_kddm_ns(int ns_id,
				void *private,
				struct kddm_ns_ops *ops)

{
	struct kddm_ns *ns;
	int error;

	ns = kmem_cache_alloc (kddm_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		return NULL;

	ns->private = private;
	ns->ops = ops;
	ns->id = ns_id;
	init_MUTEX(&ns->table_sem);
	ns->kddm_set_table = hashtable_new(KDDM_SET_HASH_TABLE_SIZE);
	init_and_set_unique_id_root(&ns->kddm_set_unique_id_root, MIN_KDDM_ID);
	atomic_set(&ns->count, 1);

	error = radix_tree_preload(GFP_KERNEL);
	if (likely(error == 0)) {
		write_lock_irq(&ns_tree_lock);
		error = radix_tree_insert(&kddm_ns_tree, ns_id, ns);
		if (unlikely(error))
			free_kddm_ns_entry(ns);

		write_unlock_irq(&ns_tree_lock);
		radix_tree_preload_end();
	}

	if (error)
		ns = ERR_PTR(error);

	return ns;
}



int remove_kddm_ns(int ns_id)
{
	struct kddm_ns *ns;

	write_lock_irq(&ns_tree_lock);
	ns = radix_tree_delete(&kddm_ns_tree, ns_id);
	write_unlock_irq(&ns_tree_lock);

	if (ns == NULL)
		return -EINVAL;

	kddm_ns_put (ns);

	return 0;
}



struct kddm_ns *kddm_ns_get(int ns_id)
{
	struct kddm_ns *ns;

	read_lock_irq(&ns_tree_lock);
	ns = radix_tree_lookup(&kddm_ns_tree, ns_id);
	if (ns)
		atomic_inc(&ns->count);
	read_unlock_irq(&ns_tree_lock);

	return ns;
}



/*****************************************************************************/
/*                                                                           */
/*                               INIT / FINALIZE                             */
/*                                                                           */
/*****************************************************************************/



void kddm_ns_init(void)
{
	kddm_ns_cachep = KMEM_CACHE(kddm_ns, SLAB_PANIC);

	INIT_RADIX_TREE(&kddm_ns_tree, GFP_ATOMIC);

	kddm_def_ns = create_kddm_ns (KDDM_DEF_NS_ID, NULL, NULL);

	BUG_ON(IS_ERR(kddm_def_ns));
}



void kddm_ns_finalize(void)
{
}
