/** DVFS mobililty interface
 *  @file mobility.h
 *
 *  Definition of DVFS mobility function interface.
 *  @author Renaud Lottiaux
 */

#ifndef __MOBILITY_H__
#define __MOBILITY_H__

#include <kerrighed/ghost.h>

struct epm_action;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   MACROS                                 *
 *                                                                          *
 *--------------------------------------------------------------------------*/
#define MAX_DVFS_MOBILITY_OPS 16

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct dvfs_mobility_operations {
  int (*file_export) (struct epm_action *,
		      ghost_t *, struct task_struct *, int, struct file *);
  int (*file_import) (struct epm_action *,
		      ghost_t *, struct task_struct *, struct file **);
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct dvfs_mobility_operations *dvfs_mobility_ops[];

enum shared_obj_type;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

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

static inline int dvfs_mobility_index (unsigned short mode)
{
	return (mode & S_IFMT) >> 12;
}

static inline void register_dvfs_mobility_ops (unsigned short mode,
					       struct dvfs_mobility_operations *ops)
{
	int index = dvfs_mobility_index (mode);

	if (index < 0 || index >= MAX_DVFS_MOBILITY_OPS) {
		printk ("Invalid index : %d\n", index);
		BUG();
	}
	else
		dvfs_mobility_ops[index] = ops;
}

static inline struct dvfs_mobility_operations *get_dvfs_mobility_ops (
	unsigned short mode)
{
	int index = dvfs_mobility_index (mode);

	if (index < 0 || index >= MAX_DVFS_MOBILITY_OPS)
		return NULL;
	else
		return dvfs_mobility_ops[index];
}

int dvfs_mobility_init(void) ;

void dvfs_mobility_finalize (void) ;

#endif // __MOBILITY_H__
