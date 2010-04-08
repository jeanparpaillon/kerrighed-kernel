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

enum file_krg_type {
	FILE,
	PIPE,
	SHM
};

struct regular_file_krg_desc {
	enum file_krg_type type;
	union {
		struct {
			fmode_t f_mode;
			int shmid;
		} shm;
		struct {
			unsigned long f_flags;
			long key;
		} pipe;
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
};

struct epm_action;
struct dvfs_file_struct;
union export_args;

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

int ghost_read_file_krg_desc(ghost_t *ghost, void **desc, int *desc_size);
int ghost_write_file_krg_desc(ghost_t *ghost, void *desc, int desc_size);

struct file *begin_import_dvfs_file(unsigned long dvfs_objid,
				    struct dvfs_file_struct **dvfs_file);

int end_import_dvfs_file(unsigned long dvfs_objid,
			 struct dvfs_file_struct *dvfs_file,
			 struct file *file, int first_import);

int cr_link_to_file(struct epm_action *action, ghost_t *ghost,
		    struct task_struct *task, struct file **returned_file);

int get_pipe_file_krg_desc(struct file *file, void **desc, int *desc_size);

int get_regular_file_krg_desc(struct file *file, void **desc,
			      int *desc_size);

int prepare_restart_data_shared_file(struct file *f,
				     void *fdesc, int fdesc_size,
				     void **returned_data, size_t *data_size,
				     bool from_substitution);

struct file *reopen_pipe_file_entry_from_krg_desc(struct task_struct *task,
						  void *_desc);

#endif // __REGULAR_FILE_MGR__
