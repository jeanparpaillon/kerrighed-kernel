/** Application management of object(s) shared by several processes
 *  @author Matthieu Fertré
 */

#ifndef __APPLICATION_SHARED_H__
#define __APPLICATION_SHARED_H__

#include <linux/rbtree.h>
#include <kerrighed/ghost_types.h>
#include <kerrighed/action.h>

/*--------------------------------------------------------------------------*/

struct app_struct;
struct app_kddm_object;
struct rpc_desc;

void clear_shared_objects(struct app_struct *app);

void destroy_shared_objects(struct app_struct *app,
			    struct task_struct *fake);

int global_chkpt_shared(struct rpc_desc *desc,
			struct app_kddm_object *obj);

int local_chkpt_shared(struct rpc_desc *desc,
		       struct app_struct *app,
		       int chkpt_sn);

int global_restart_shared(struct rpc_desc *desc,
			  struct app_kddm_object *obj,
			  struct restart_request *req);

int local_restart_shared(struct rpc_desc *desc,
			 struct app_struct *app,
			 struct task_struct *fake,
			 int chkpt_sn);

int local_restart_shared_complete(struct app_struct *app,
				  struct task_struct *fake);

/*--------------------------------------------------------------------------*/

enum shared_obj_type {
	/* things to restore before files */
	PIPE_INODE,

	/* file descriptors */
	LOCAL_FILE,
	DVFS_FILE,

	/* other objects */
	FILES_STRUCT,
	FS_STRUCT,
	MM_STRUCT,
	SEMUNDO_LIST,
	SIGHAND_STRUCT,
	SIGNAL_STRUCT,
	NO_OBJ
};

struct file_export_args {
	int index;
	struct file *file;
};

union export_args {
	struct file_export_args file_args;
};

struct export_obj_info {
	struct task_struct *task;
	struct list_head next;
	union export_args args;
};

enum object_locality {
	LOCAL_ONLY,
	SHARED_ANY,
	SHARED_MASTER,
	SHARED_SLAVE
};

int add_to_shared_objects_list(struct app_struct *app,
			       enum shared_obj_type type,
			       unsigned long key,
			       enum object_locality locality,
			       struct task_struct* exporting_task,
			       union export_args *args,
			       int force);

void *get_imported_shared_object(struct app_struct *app,
				 enum shared_obj_type type,
				 unsigned long key);

struct shared_object_operations {
	size_t restart_data_size;
	int (*export_now) (struct epm_action *, ghost_t *, struct task_struct *,
			   union export_args *);

	/* export_user_info is used to export information to a readable file to
	 * userspace
	 */
	int (*export_user_info) (struct epm_action *, ghost_t *, unsigned long,
				 struct export_obj_info *);

	int (*import_now) (struct epm_action *, ghost_t *, struct task_struct *,
			   int, void  **, size_t *);
	int (*import_complete) (struct task_struct *, void *);
	int (*delete) (struct task_struct *, void *);
};

#endif
