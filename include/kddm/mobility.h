/** Process Virtual Memory mobililty interface
 *  @file vm_mobility.h
 *
 *  Definition of VM mobility function interface.
 *  @author Renaud Lottiaux
 */

#ifndef __KDDM_MOBILITY_H__
#define __KDDM_MOBILITY_H__

#include <kerrighed/ghost.h>

struct epm_action;
struct task_struct;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



int export_kddm_info_struct (struct epm_action *action,
			     ghost_t *ghost, struct task_struct *tsk);
int import_kddm_info_struct (struct epm_action *action,
			     ghost_t *ghost, struct task_struct *tsk);
void unimport_kddm_info_struct (struct task_struct *tsk);


#endif // __KDDM_MOBILITY_H__
