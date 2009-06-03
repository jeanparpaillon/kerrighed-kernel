/** KDDM object tree based on page tables.
 *  @file page_table_tree.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __PAGE_TABLE_TREE__
#define __PAGE_TABLE_TREE__

#include <kddm/kddm_types.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct kddm_set_ops kddm_pt_set_ops;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



int kddm_pt_invalidate (struct kddm_set *set, objid_t objid,
			struct kddm_obj *obj_entry, struct page *page);

#endif // __PAGE_TABLE_TREE__
