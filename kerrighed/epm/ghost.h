/**
 *  Definition of process mobility function interface.
 *  @author Geoffroy Vallée
 */

#ifndef __EPM_GHOST_H__
#define __EPM_GHOST_H__

#include <kerrighed/ghost_types.h>

struct task_struct;
struct pt_regs;
struct epm_action;

/**
 *  Export a process into a ghost.
 *  @author  Geoffroy Vallée
 *
 *  @param action	Type of export.
 *  @param ghost	Ghost to export the task to.
 *  @param task		Task to export.
 *  @param regs		Userspace registers of the task.
 *
 *  @return		0 if everything ok.
 *			Negative value otherwise.
 */
int export_process(struct epm_action *action,
		   ghost_t *ghost,
		   struct task_struct *task,
		   struct pt_regs *regs);
void post_export_process(struct epm_action *action,
			 ghost_t *ghost,
			 struct task_struct *task);

/**
 *  Import a process from a ghost.
 *  @author  Geoffroy Vallée
 *
 *  @param action	Type of import.
 *  @param ghost	Ghost to import the task from.

 *  @return		Pointer to the imported task struct.
 */
struct task_struct *import_process(struct epm_action *action,
				   ghost_t *ghost);

#endif /* __EPM_GHOST_H__ */
