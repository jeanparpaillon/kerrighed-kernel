/** Implementation of KDDM mobility mechanisms.
 *  @file mobility.c
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 *
 *  Implementation of functions used to migrate, duplicate and checkpoint
 *  process KDDM related structures.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <kddm/kddm_types.h>

#include <kerrighed/ghost.h>
#include <kerrighed/action.h>


int initialize_kddm_info_struct (struct task_struct *task);
extern struct kmem_cache *kddm_info_cachep;



/*****************************************************************************/
/*                                                                           */
/*                              EXPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



/** Export a KDDM info structure
 *  @author Renaud Lottiaux
 *
 *  @param ghost    Ghost where data should be stored.
 *  @param tsk      The task to ghost the KDDM info struct for.
 *
 *  @return  0 if everything was OK.
 *           Negative value otherwise.
 */
int export_kddm_info_struct (struct epm_action *action,
			     ghost_t *ghost,
			     struct task_struct *tsk)
{
	int r = 0;

	if (tsk->exit_state)
		return 0;

	BUG_ON (tsk->kddm_info == NULL);

	switch (action->type) {
	  case EPM_REMOTE_CLONE:
		  /* */
		  break;

	  case EPM_CHECKPOINT:
	  case EPM_MIGRATE:
		  r = ghost_write (ghost, tsk->kddm_info,
				   sizeof(struct kddm_info_struct));
		  break;

	  default:
		  BUG();
		  r = -EINVAL;
		  break;
	}

	return r;
}



/*****************************************************************************/
/*                                                                           */
/*                              IMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



int import_kddm_info_struct (struct epm_action *action,
			     ghost_t *ghost,
			     struct task_struct *tsk)
{
	struct kddm_info_struct *kddm_info;
	int r;

	if (tsk->exit_state) {
		tsk->kddm_info = NULL;
		return 0;
	}

	switch (action->type) {
	  case EPM_REMOTE_CLONE:
		  r = initialize_kddm_info_struct (tsk);
		  break;

	  case EPM_RESTART:
	  case EPM_MIGRATE:
		  r = -ENOMEM;
		  kddm_info = kmem_cache_alloc(kddm_info_cachep,
					       GFP_KERNEL);

		  if (!kddm_info)
			break;

		  r = ghost_read (ghost, kddm_info,
				  sizeof(struct kddm_info_struct));
		  if (r) {
			kmem_cache_free(kddm_info_cachep, kddm_info);
			break;
		  }

		  kddm_info->wait_obj = NULL;

		  tsk->kddm_info = kddm_info;

		  break;

	  default:
		  BUG();
		  r = -EINVAL;
	}

	return r;
}



/*****************************************************************************/
/*                                                                           */
/*                            UNIMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



void unimport_kddm_info_struct (struct task_struct *tsk)
{
	if (!tsk->exit_state)
		kmem_cache_free (kddm_info_cachep, tsk->kddm_info);
}
