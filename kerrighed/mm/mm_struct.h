/** Distributed management of the MM structure.
 *  @file mm_struct.h
 *
 *  @author Renaud Lottiaux.
 */


#ifndef MM_STRUCT_H
#define MM_STRUCT_H

#include <kddm/kddm_get_object.h>
#include <kddm/kddm_grab_object.h>
#include <kddm/kddm_put_object.h>

struct anon_vma_kddm_set_private {
	pid_t last_pid;
	pid_t last_tgid;
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct kddm_set *mm_struct_kddm_set;

extern unique_id_root_t mm_struct_unique_id_root;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/


struct mm_struct *alloc_fake_mm(struct mm_struct *src_mm);
int reinit_mm(struct mm_struct *mm);


int init_anon_vma_kddm_set(struct task_struct *tsk,
			   struct mm_struct *mm);

struct mm_struct *krg_dup_mm(struct task_struct *tsk,struct mm_struct *src_mm);

static inline struct mm_struct *krg_get_mm(unique_id_t mm_id)
{
	if (mm_id)
		return _kddm_get_object (mm_struct_kddm_set, mm_id);
	else
		return NULL;
}

static inline struct mm_struct *krg_grab_mm(unique_id_t mm_id)
{
	if (mm_id)
		return _kddm_grab_object (mm_struct_kddm_set, mm_id);
	else
		return NULL;
}

void kcb_mm_get(struct mm_struct *mm);

static inline void krg_put_mm(unique_id_t mm_id)
{
	if (mm_id)
		_kddm_put_object (mm_struct_kddm_set, mm_id);
}

void mm_struct_finalize (void);
void mm_struct_init (void);

#endif // MM_STRUCT_H
