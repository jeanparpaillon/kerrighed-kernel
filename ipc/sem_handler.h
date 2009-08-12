/** Interface of IPC semaphore (sem) management.
 *  @file sem_handler.h
 *
 *  @author Matthieu Fertré
 */
#ifndef SEM_HANDLER_H
#define SEM_HANDLER_H

#include <linux/sem.h>

int share_existing_semundo_proc_list(struct task_struct *tsk,
				     unique_id_t undo_list_id);
int create_semundo_proc_list(struct task_struct *tsk);
void destroy_semundo_proc_list(struct task_struct *task,
			       unique_id_t undo_list_id);

void sem_handler_init(void);
void sem_handler_finalize(void);

#endif // SEM_HANDLER_H
