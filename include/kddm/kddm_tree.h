/** Kddm tree implementation.
 *  @file kddm_tree.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_TREE__
#define __KDDM_TREE__

#include <linux/spinlock.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define _2LEVELS_KDDM_TREE 0
#define _NLEVELS_KDDM_TREE 1

#define KDDM_TREE_ADD_ENTRY 1



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct kddm_set_ops kddm_tree_set_ops;
extern void *_2levels_kddm_tree_init_data;
extern void *_nlevels_kddm_tree_init_data;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   TYPES                                  *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** KDDM tree level struct type */
struct kddm_tree_lvl {
	int nr_obj;
	struct kddm_tree_lvl **sub_lvl;
};

/** KDDM tree type */
struct kddm_tree {
	struct kddm_tree_lvl *lvl1;
	unsigned long max_data;
	spinlock_t table_lock;       /**< Object table lock */
	int tree_type;
	int nr_level;
	int bit_width; /*!< width of index 20, 32, 64 */
	int bit_size; /*!< normal bits per level, last level is the rest  */
	int bit_size_last; /*!< bits for last level (zero, if width%size=0) */
};

#endif // __KDDM_TREE__
