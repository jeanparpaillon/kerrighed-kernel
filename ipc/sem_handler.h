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

struct kddm_set;

struct kddm_set *krgipc_ops_undolist_set(struct krgipc_ops *ipcops);
struct kddm_set *task_undolist_set(struct task_struct *task);

struct semundo_list_object;
int add_semundo_to_proc_list(struct semundo_list_object *undo_list, int semid);

int krg_sem_flush_set(struct ipc_namespace *ns);

void sem_handler_init(void);
void sem_handler_finalize(void);

#endif // SEM_HANDLER_H
