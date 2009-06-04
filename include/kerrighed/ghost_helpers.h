#ifndef __GHOST_HELPERS_H__
#define __GHOST_HELPERS_H__

#include <kerrighed/ghost_types.h>

struct epm_action;
struct task_struct;
enum shared_obj_type;

/* KDDM */

int export_kddm_info_struct (struct epm_action *action,
			     ghost_t *ghost, struct task_struct *tsk);
int import_kddm_info_struct (struct epm_action *action,
			     ghost_t *ghost, struct task_struct *tsk);
void unimport_kddm_info_struct (struct task_struct *tsk);

/* MM */

/**
 *  This function exports the virtual memory of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where VM data should be stored.
 *  @param task    Task to export file data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_mm_struct (struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task);


/**
 *  This function imports the virtual memory of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where VM data are stored.
 *  @param task    Task to load VM data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_mm_struct (struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task);

void unimport_mm_struct(struct task_struct *task);

/**
 *  Free the mm struct of the ghost process.
 *
 *  @param task    Task struct of the ghost process.
 */
void free_ghost_mm (struct task_struct *task);

/* FS */

/** Export an files structure into a ghost.
 *  @author  Renaud Lottiaux
 *
 *  @param ghost  Ghost where files data should be stored.
 *  @param tsk    Task to export files data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_files_struct (struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk);

/** Export the fs_struct of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be stored.
 *  @param tsk    Task to export file data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_fs_struct (struct epm_action *action,
		      ghost_t *ghost, struct task_struct *tsk);

int export_vma_file (struct epm_action *action, ghost_t * ghost,
                     struct task_struct *tsk, struct vm_area_struct *vma);

int export_mnt_namespace (struct epm_action *action,
			  ghost_t *ghost, struct task_struct *tsk);

/** Import a files structure from a ghost.
 *  @author  Renaud Lottiaux
 *
 *  @param ghost  Ghost where files data are stored.
 *  @param tsk    Task to load files data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_files_struct (struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk);

/** Import the fs_struct of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data are stored.
 *  @param tsk    Task to import file data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_fs_struct (struct epm_action *action,
		      ghost_t *ghost, struct task_struct *tsk);

int import_vma_file (struct epm_action *action, ghost_t *ghost,
                     struct task_struct *tsk, struct vm_area_struct *vma);

int import_mnt_namespace (struct epm_action *action,
			  ghost_t *ghost, struct task_struct *tsk);

void unimport_mnt_namespace(struct task_struct *task);
void unimport_files_struct(struct task_struct *task);
void unimport_fs_struct(struct task_struct *task);

void free_ghost_files (struct task_struct *ghost);

void cr_get_file_type_and_key(const struct file *file,
			      enum shared_obj_type *type,
			      long *key);

int cr_add_file_to_shared_table(struct task_struct *task,
				int index, struct file *file);

int cr_link_to_file(struct epm_action *action, ghost_t *ghost,
		    struct task_struct *task, struct file **returned_file);

/* IPC */

int get_shm_file_krg_desc(struct file *file, void **desc, int *desc_size);

struct file *reopen_shm_file_entry_from_krg_desc(struct task_struct *task,
						 void *desc);

int export_ipc_namespace(struct epm_action *action,
                         ghost_t *ghost, struct task_struct *task);
int import_ipc_namespace(struct epm_action *action,
                         ghost_t *ghost, struct task_struct *task);
void unimport_ipc_namespace(struct task_struct *task);

int export_sysv_sem(struct epm_action *action,
                    ghost_t *ghost, struct task_struct *task);
int import_sysv_sem(struct epm_action *action,
                    ghost_t *ghost, struct task_struct *task);
void unimport_sysv_sem(struct task_struct *task);

#endif /* __GHOST_HELPERS_H__ */
