/** KDDM tree management.
 *  @file kddm_tree.c
 *
 *  Copyright (C) 2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/mm.h>

#include <net/krgrpc/rpc.h>
#include <kddm/kddm_tree.h>
#include <kddm/kddm_types.h>
#include <kddm/object.h>

struct kmem_cache *kddm_tree_cachep;
struct kmem_cache *kddm_tree_lvl_cachep;

int _2levels_kddm_tree = _2LEVELS_KDDM_TREE;
int _nlevels_kddm_tree = _NLEVELS_KDDM_TREE;
void *_2levels_kddm_tree_init_data = (void*)&_2levels_kddm_tree;
void *_nlevels_kddm_tree_init_data = (void*)&_nlevels_kddm_tree;



/*****************************************************************************/
/*                                                                           */
/*                              HELPER FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



static inline int lvl_bits(struct kddm_tree *tree, int level)
{
	if (level < tree->nr_level - 1 || !tree->bit_size_last)
		return tree->bit_size;
	return tree->bit_size_last;
}

static inline int lvl_shift(struct kddm_tree *tree, int level)
{
	return (tree->nr_level - 1 - level) * tree->bit_size;
}

static inline unsigned long
lvl_sub_index(struct kddm_tree *tree, int level, unsigned long index)
{
	int bits = lvl_bits(tree, level);

	return (index >> lvl_shift(tree, level)) & ((1UL << bits) - 1UL);
}



/*****************************************************************************/
/*                                                                           */
/*                               CORE TREE CODE                              */
/*                                                                           */
/*****************************************************************************/



/** Lookup for a data in a kddm tree.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to lookup.
 *
 *  @return The data if found.
 *          NULL if the data is not found.
 */
static void *kddm_tree_lookup (struct kddm_tree *tree,
			       unsigned long index)
{
	struct kddm_tree_lvl *cur_level;
	int sub_index, i;

	BUG_ON (tree == NULL);

	if (tree->lvl1 == NULL)
		return NULL;

	cur_level = tree->lvl1;

	for (i = 0; i < tree->nr_level; i++) {
		sub_index = lvl_sub_index(tree, i, index);
		cur_level = cur_level->sub_lvl[sub_index];
		if (cur_level == NULL)
			break;
	}

	return cur_level;
}



/** Lookup for a data in a kddm tree and allocated slots if needed.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to lookup.
 *
 *  @return The address of the slot hosting the data.
 *          If the data does not exist, an empty slot is allocated.
 */
static void **kddm_tree_lookup_slot (struct kddm_tree *tree,
				     unsigned long index,
				     int flags)
{
	struct kddm_tree_lvl *cur_level, *prev_level;
	int sub_index, nr_entries, i;
	void *data;

	BUG_ON (tree == NULL);

	prev_level = NULL;
	cur_level = tree->lvl1;
	sub_index = 0;

	for (i = 0; i < tree->nr_level; i++) {
		if (cur_level == NULL) {
			nr_entries = 1UL << lvl_bits(tree, i);

			cur_level = kmem_cache_alloc (kddm_tree_lvl_cachep,
						      GFP_ATOMIC);
			cur_level->sub_lvl = kmalloc(
				sizeof(struct kddm_tree_lvl *) * nr_entries,
				GFP_ATOMIC);
			cur_level->nr_obj = 0;

			memset(cur_level->sub_lvl, 0,
			       sizeof(struct kddm_tree_lvl *) * nr_entries);

			if (i == 0)
				tree->lvl1 = cur_level;
			else {
			        prev_level->sub_lvl[sub_index] = cur_level;
				prev_level->nr_obj++;
			}
		}
		sub_index = lvl_sub_index(tree, i, index);

		prev_level = cur_level;
		cur_level = cur_level->sub_lvl[sub_index];
	}

	data = prev_level->sub_lvl[sub_index];
	if ((flags & KDDM_TREE_ADD_ENTRY) && (data == NULL))
		prev_level->nr_obj++;

	return (void **)&(prev_level->sub_lvl[sub_index]);
}



/** Lookup for a data in a kddm tree and allocated slots if needed.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to lookup.
 *
 *  @return The address of the slot hosting the data.
 *          If the data does not exist, an empty slot is allocated.
 */
static void *__kddm_tree_remove (struct kddm_set *set,
				 struct kddm_tree_lvl *cur_level,
				 int level,
				 unsigned long index,
				 int *_sub_level_freed)
{
	struct kddm_tree *tree = set->obj_set;
	struct kddm_tree_lvl *sub_level;
	int sub_index, sub_level_freed = 0;
	struct kddm_obj *obj_entry;

	sub_index = lvl_sub_index(tree, level, index);

	if ((level + 1) == tree->nr_level) {
		obj_entry = (struct kddm_obj *)cur_level->sub_lvl[sub_index];
		goto free_sub_level_slot;
	}

	sub_level = cur_level->sub_lvl[sub_index];
	if (sub_level == NULL)
		return NULL;

	obj_entry = __kddm_tree_remove(set, sub_level, level+1, index,
				       &sub_level_freed);
	if (sub_level_freed)
		goto free_sub_level_slot;
	return obj_entry;

free_sub_level_slot:
	cur_level->sub_lvl[sub_index] = NULL;
	cur_level->nr_obj--;
	if (cur_level->nr_obj == 0) {
		kfree (cur_level->sub_lvl);
		kmem_cache_free(kddm_tree_lvl_cachep, cur_level);
		*_sub_level_freed = 1;
	}
	return obj_entry;
}



/** Remove a data from a kddm tree.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to remove.
 */
static void *kddm_tree_remove(struct kddm_set *set,
			      unsigned long index)
{
	void *data;
	int sub_level_freed = 0;
	struct kddm_tree *tree = set->obj_set;

	data = __kddm_tree_remove(set, tree->lvl1, 0, index,
				  &sub_level_freed);

	if (sub_level_freed)
		tree->lvl1 = NULL;

	return data;
}

static int __kddm_tree_for_each_level(struct kddm_set *set,
				      struct kddm_tree_lvl *cur_level,
				      int level,
				      unsigned long index,
				      int free,
				      struct kddm_obj_iterator *iterator)
{
	int i, sub_level_freed = 0;
	struct kddm_tree_lvl *sub_level;
	struct kddm_tree *tree = set->obj_set;
	unsigned long index_gap = 1UL << lvl_shift(tree, level);
	int res;

	for (i = 0; i < (1UL << lvl_bits(tree, level)); i++) {
retry:
		sub_level = cur_level->sub_lvl[i];
		if (sub_level != NULL) {
			if ((level + 1) == tree->nr_level) {
				struct kddm_obj *obj_entry;

				obj_entry = (struct kddm_obj *)sub_level;

				res = do_func_on_obj_entry(set, obj_entry,
							   index, iterator);
				if (res == -EAGAIN)
					goto retry;

				sub_level_freed = (res == KDDM_OBJ_REMOVED);
			}
			else
				sub_level_freed =
				    __kddm_tree_for_each_level(set, sub_level,
							   level+1, index, free,
							   iterator);
			if (sub_level_freed) {
				cur_level->sub_lvl[i] = NULL;
				cur_level->nr_obj--;
				if (cur_level->nr_obj == 0)
					goto free_level;
				sub_level_freed = 0;
			}
		}
		index += index_gap ;
	}
	if (!free)
		return 0;
free_level:
	kfree (cur_level->sub_lvl);
	kmem_cache_free(kddm_tree_lvl_cachep, cur_level);
	return 1;
}

static inline void __kddm_tree_for_each(struct kddm_set *set,
					int free,
					struct kddm_obj_iterator *iterator)
{
	struct kddm_tree *tree = set->obj_set;

	if (tree->lvl1 == NULL)
		return;
	if (__kddm_tree_for_each_level(set, tree->lvl1, 0, 0, free, iterator))
		tree->lvl1 = NULL;
}



/** Executes a function for each data in a tree.
 *  @param tree      The tree.
 *  @param f         The function to execute for each data.
 *  @param priv      Private data passed to the function.
 */
static void kddm_tree_for_each(struct kddm_set *set,
			       struct kddm_obj_iterator *iterator)
{
	__kddm_tree_for_each(set, 0, iterator);
}



/** Alloc a KDDM tree.
 *  @param tree_type   The tree type :)
 *
 *  @return   A newly allocated tree.
 */
static void *kddm_tree_alloc (struct kddm_set *set, void *data)
{
	struct kddm_tree *tree;
	int width, bit_size;
	int tree_type = *((int*)data);

	tree = kmem_cache_alloc (kddm_tree_cachep, GFP_KERNEL);
	if (tree == NULL)
		return NULL;

	tree->lvl1 = NULL;
	tree->tree_type = tree_type;

	switch (tree_type) {
	case _2LEVELS_KDDM_TREE:
		width = 20;
		bit_size = 10;
		break;

	case _NLEVELS_KDDM_TREE:
		width = BITS_PER_LONG;
		bit_size = 8;
		break;

	default:
		  printk ("Unknown KDDM tree type %d\n", tree_type);
		  BUG();
	}
	tree->bit_width = width;
	tree->max_data = (-1UL) >> (BITS_PER_LONG - width);
	tree->bit_size = bit_size;
	tree->nr_level = width / bit_size;
	spin_lock_init(&tree->table_lock);
	if (width % bit_size) {
		tree->bit_size_last = width % bit_size;
		tree->nr_level++;
	} else
		tree->bit_size_last = 0;

	return tree;
}



/** Delete a KDDM tree.
 *  @param tree_type   The tree to delete.
 *  @param f           A function to call on each found data.
 *  @param priv        Private data passed to the function.
 */
static void kddm_tree_free (struct kddm_set *set,
			    struct kddm_obj_iterator *iterator)
{
	__kddm_tree_for_each(set, 1, iterator);

	kmem_cache_free(kddm_tree_cachep, set->obj_set);
}



/*****************************************************************************/
/*                                                                           */
/*                             KDDM SET OPERATIONS                           */
/*                                                                           */
/*****************************************************************************/



static struct kddm_obj *kddm_tree_lookup_obj_entry (struct kddm_set *set,
						    objid_t objid)
{
	struct kddm_obj *obj_entry;

	obj_entry = kddm_tree_lookup(set->obj_set, objid);

	return obj_entry;
}



static struct kddm_obj *kddm_tree_get_obj_entry (struct kddm_set *set,
						 objid_t objid,
						 struct kddm_obj *new_obj)
{
	struct kddm_obj **obj_ptr, *obj_entry;

	obj_ptr = (struct kddm_obj **)kddm_tree_lookup_slot(set->obj_set,
					    objid, KDDM_TREE_ADD_ENTRY);

	if (*obj_ptr == NULL)
		*obj_ptr = new_obj;

	obj_entry = *obj_ptr;
	return obj_entry;
}



static void kddm_tree_remove_obj_entry (struct kddm_set *set,
					objid_t objid)
{
	kddm_tree_remove (set, objid);
}



static void kddm_tree_for_each_obj_entry(struct kddm_set *set,
					 struct kddm_obj_iterator *iterator)
{
	kddm_tree_for_each(set, iterator);
}



static void kddm_tree_export (struct rpc_desc* desc, struct kddm_set *set)
{
	struct kddm_tree *tree = set->obj_set;

	rpc_pack_type(desc, tree->tree_type);
}



static void *kddm_tree_import (struct rpc_desc* desc, int *free_data)
{
	int *tree_type;

	tree_type = kmalloc (sizeof (int), GFP_KERNEL);
	*free_data = 1;

	rpc_unpack(desc, 0, tree_type, sizeof (int));
	return tree_type;
}

static void kddm_tree_lock_obj_table (struct kddm_set *set)
{
	struct kddm_tree *tree = set->obj_set;

	spin_lock (&tree->table_lock);
}

static void kddm_tree_unlock_obj_table (struct kddm_set *set)
{
	struct kddm_tree *tree = set->obj_set;

	spin_unlock (&tree->table_lock);
}

struct kddm_set_ops kddm_tree_set_ops = {
	obj_set_alloc:       kddm_tree_alloc,
	obj_set_free:        kddm_tree_free,
	lookup_obj_entry:    kddm_tree_lookup_obj_entry,
	get_obj_entry:       kddm_tree_get_obj_entry,
	remove_obj_entry:    kddm_tree_remove_obj_entry,
	for_each_obj_entry:  kddm_tree_for_each_obj_entry,
	export:              kddm_tree_export,
	import:              kddm_tree_import,
	lock_obj_table:      kddm_tree_lock_obj_table,
	unlock_obj_table:    kddm_tree_unlock_obj_table,
};
