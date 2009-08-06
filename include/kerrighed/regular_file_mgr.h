/** Global management of regular files interface.
 *  @file regular_file_mgr.h
 *
 *  @author Renaud Lottiaux
 */
#ifndef __REGULAR_FILE_MGR__
#define __REGULAR_FILE_MGR__

#include <kddm/kddm_types.h>
#include <kerrighed/ghost.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

typedef struct regular_file_krg_desc {
	int sysv;
	union {
		struct {
			fmode_t f_mode;
			int shmid;
		} shm;
		struct {
			umode_t mode;
			loff_t pos;
			unsigned int flags;
			unsigned int uid;
			unsigned int gid;
			kddm_set_id_t ctnrid;
			char *filename;
		} file;
	};
} regular_file_krg_desc_t;

struct epm_action;
struct dvfs_file_struct;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct dvfs_mobility_operations dvfs_mobility_regular_ops;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int ghost_read_file_krg_desc(ghost_t *ghost, void **desc);
int ghost_write_file_krg_desc(ghost_t *ghost, void *desc, int desc_size);
int ghost_write_regular_file_krg_desc(ghost_t *ghost, struct file *file);

int get_regular_file_krg_desc(struct file *file, void **desc, int *desc_size);

struct file *begin_import_dvfs_file(unsigned long dvfs_objid,
				    struct dvfs_file_struct **dvfs_file);

int end_import_dvfs_file(unsigned long dvfs_objid,
			 struct dvfs_file_struct *dvfs_file,
			 struct file *file, int first_import);

struct file *import_regular_file_from_krg_desc(struct task_struct *task,
					       void *_desc);

int cr_link_to_local_regular_file(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task,
				  struct file **returned_file,
				  long key);

int cr_link_to_dvfs_regular_file(struct epm_action *action, ghost_t *ghost,
				 struct task_struct *task,
				 void *desc,
				 struct file **returned_file,
				 long key);

#endif // __REGULAR_FILE_MGR__
