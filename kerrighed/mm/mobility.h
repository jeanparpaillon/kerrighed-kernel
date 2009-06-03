/** Process Virtual Memory mobililty interface
 *  @file vm_mobility.h
 *
 *  Definition of VM mobility function interface.
 *  @author Renaud Lottiaux
 */

#ifndef __VM_MOBILITY_H__
#define __VM_MOBILITY_H__

#include <kerrighed/ghost.h>

struct epm_action;


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/


void partial_init_vma(struct mm_struct *mm, struct vm_area_struct *vma);


/** This function exports the virtual memory of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where VM data should be stored.
 *  @param tsk    Task to export file data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_mm_struct (struct epm_action *action,
		      ghost_t *ghost, struct task_struct *tsk);


/** This function imports the virtual memory of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where VM data are stored.
 *  @param tsk    Task to load VM data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_mm_struct (struct epm_action *action,
		      ghost_t *ghost, struct task_struct *tsk);


void unimport_mm_struct(struct task_struct *task);



/** Free the mm struct of the ghost process.
 *
 *  @param tsk    Task struct of the ghost process.
 */
void free_ghost_mm (struct task_struct *tsk);



#endif // __VM_MOBILITY_H__
