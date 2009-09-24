#ifndef __GHOST_HELPERS_H__
#define __GHOST_HELPERS_H__

#include <kerrighed/ghost_types.h>
#include <linux/hashtable.h>

struct epm_action;
struct task_struct;
struct restart_block;
struct pid_link;
struct pid;
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

int export_mm_exe_file(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *tsk);

int export_vma_file (struct epm_action *action, ghost_t * ghost,
		     struct task_struct *tsk, struct vm_area_struct *vma,
		     hashtable_t *file_table);

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

int import_mm_exe_file(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *tsk);

int import_vma_file (struct epm_action *action, ghost_t *ghost,
		     struct task_struct *tsk, struct vm_area_struct *vma,
		     hashtable_t *file_table);

int import_mnt_namespace (struct epm_action *action,
			  ghost_t *ghost, struct task_struct *tsk);

void unimport_files_struct(struct task_struct *task);
void unimport_fs_struct(struct task_struct *task);

void free_ghost_files (struct task_struct *ghost);

void cr_get_file_type_and_key(const struct file *file,
			      enum shared_obj_type *type,
			      long *key,
			      int allow_unsupported);

int cr_add_file_to_shared_table(struct task_struct *task,
				int index, struct file *file,
				int allow_unsupported);

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

/* EPM */

/* Arch-dependent helpers */

void prepare_to_export(struct task_struct *task);

int export_thread_info(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task);
int import_thread_info(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *task);
void unimport_thread_info(struct task_struct *task);
void free_ghost_thread_info(struct task_struct *);

int export_thread_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk);
int import_thread_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk);
void unimport_thread_struct(struct task_struct *task);

/* Generic helpers for arch-dependent helpers */

int export_exec_domain(struct epm_action *action,
		       ghost_t *ghost, struct task_struct *tsk);
struct exec_domain *import_exec_domain(struct epm_action *action,
				       ghost_t *ghost);

int export_restart_block(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk);
int import_restart_block(struct epm_action *action,
			 ghost_t *ghost, struct restart_block *p);

/* Signals */

int export_signal_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task);
int import_signal_struct(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task);
void unimport_signal_struct(struct task_struct *task);

int export_private_signals(struct epm_action *action,
			   ghost_t *ghost,
			   struct task_struct *task);
int import_private_signals(struct epm_action *action,
			   ghost_t *ghost,
			   struct task_struct *task);
void unimport_private_signals(struct task_struct *task);

int export_sighand_struct(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task);
int import_sighand_struct(struct epm_action *action,
			  ghost_t *ghost, struct task_struct *task);
void unimport_sighand_struct(struct task_struct *task);

/* Pids */

int export_pid(struct epm_action *action,
	       ghost_t *ghost, struct pid_link *link);
int export_pid_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task);

int import_pid(struct epm_action *action,
	       ghost_t *ghost, struct pid_link *link);
int import_pid_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task);
void krg_end_get_pid(struct pid *pid);

void unimport_pid(struct pid_link *link);

/* Misc */

int export_sched(struct epm_action *action,
		 ghost_t *ghost, struct task_struct *tsk);
int import_sched(struct epm_action *action,
		 ghost_t *ghost, struct task_struct *task);
static inline void unimport_sched(struct task_struct *task)
{
}

int export_vfork_done(struct epm_action *action,
		      ghost_t *ghost, struct task_struct *tsk);
int import_vfork_done(struct epm_action *action,
		      ghost_t *ghost, struct task_struct *task);
void unimport_vfork_done(struct task_struct *task);

int export_cred(struct epm_action *action,
		ghost_t *ghost, struct task_struct *tsk);
int import_cred(struct epm_action *action,
		ghost_t *ghost, struct task_struct *task);
void unimport_cred(struct task_struct *task);
void free_ghost_cred(struct task_struct *ghost);

#ifdef CONFIG_AUDITSYSCALL
int export_audit_context(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk);
int import_audit_context(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task);
void unimport_audit_context(struct task_struct *task);
void free_ghost_audit_context(struct task_struct *ghost);
#else /* !CONFIG_AUDITSYSCALL */
static inline
int export_audit_context(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *tsk)
{
	return 0;
}
static inline
int import_audit_context(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	return 0;
}
static inline void unimport_audit_context(struct task_struct *task)
{
}
static inline void free_ghost_audit_context(struct task_struct *ghost)
{
}
#endif /* !CONFIG_AUDITSYSCALL */

int export_cgroups(struct epm_action *action,
		   ghost_t *ghost, struct task_struct *task);
int import_cgroups(struct epm_action *action,
		   ghost_t *ghost, struct task_struct *task);
void unimport_cgroups(struct task_struct *task);
void free_ghost_cgroups(struct task_struct *ghost);

/* SCHED */

#ifdef CONFIG_KRG_SCHED

int export_krg_sched_info(struct epm_action *action, struct ghost *ghost,
			  struct task_struct *task);
int import_krg_sched_info(struct epm_action *action, struct ghost *ghost,
			  struct task_struct *task);
void post_import_krg_sched_info(struct task_struct *task);
void unimport_krg_sched_info(struct task_struct *task);

int export_process_set_links_start(struct epm_action *action, ghost_t *ghost,
				   struct task_struct *task);
int export_process_set_links(struct epm_action *action, ghost_t *ghost,
			     struct pid *pid, enum pid_type type);
void export_process_set_links_end(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task);

int import_process_set_links(struct epm_action *action, ghost_t *ghost,
			     struct pid *pid, enum pid_type type);

#endif /* CONFIG_KRG_SCHED */

#endif /* __GHOST_HELPERS_H__ */
