/** DVFS Level 3 - File struct sharing management.
 *  @file file.c
 *
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/file.h>
#include <linux/unique_id.h>
#include <linux/sched.h>
#include <kerrighed/dvfs.h>

#ifdef CONFIG_KRG_FAF
#include <kerrighed/faf_file_mgr.h>
#include "faf/faf_hooks.h"
#include "faf/faf_internal.h"
#endif

#include <kddm/kddm.h>
#include <kerrighed/hotplug.h>
#ifdef CONFIG_KRG_EPM
#include <kerrighed/action.h>
#endif
#include <kerrighed/file.h>
#include "file_struct_io_linker.h"

/* Unique DVFS file struct id generator root */
unique_id_root_t file_struct_unique_id_root;

/* DVFS file struct container */
struct kddm_set *dvfs_file_struct_ctnr = NULL;

int create_kddm_file_object(struct file *file)
{
	struct dvfs_file_struct *dvfs_file;
	unsigned long file_id;

	file_id = get_unique_id (&file_struct_unique_id_root);

	dvfs_file = grab_dvfs_file_struct(file_id);
	BUG_ON (dvfs_file->file != NULL);

	dvfs_file->f_pos = file->f_pos;
	dvfs_file->count = 1;
	dvfs_file->file = NULL;

	/* Make sure we don't put the same file struct in 2 different objects.
	 * The first writing in file->f_objid wins.
	 * The second one is destroyed. We assume this is really unlikely.
	 */
	if (cmpxchg (&file->f_objid, 0, file_id) != 0)
		_kddm_remove_frozen_object(dvfs_file_struct_ctnr, file_id);
	else {
		dvfs_file->file = file;
		put_dvfs_file_struct (file_id);
	}

	return 0;
}

#ifdef CONFIG_KRG_EPM
/** Check if we need to share a file struct cluster wide and do whatever needed
 *  @author Renaud Lottiaux
 *
 *  @param file    Struct of the file to check the sharing.
 */
void check_file_struct_sharing (int index, struct file *file,
				struct epm_action *action)
{
	/* Do not share the file struct for FAF files or already shared files*/
	if (file->f_flags & (O_FAF_CLT | O_FAF_SRV | O_KRG_SHARED))
		goto done;

#ifdef CONFIG_KRG_IPC
	BUG_ON(file->f_op == &krg_shm_file_operations);

	/* Do not share the file struct for Kerrighed SHM files */
	if (file->f_op == &shm_file_operations)
		goto done;
#endif

	switch (action->type) {
	  case EPM_CHECKPOINT:
		  goto done;

	  case EPM_REMOTE_CLONE:
		  goto share;

	  case EPM_MIGRATE:
		  if (file_count(file) == 1)
			  goto done;
		  break;

	  default:
		  BUG();
	}

share:
	file->f_flags |= O_KRG_SHARED;

done:
	return;
}
#endif

void get_dvfs_file(int index, unsigned long objid)
{
	struct dvfs_file_struct *dvfs_file;
	struct file *file;

	dvfs_file = grab_dvfs_file_struct(objid);
	file = dvfs_file->file;

	dvfs_file->count++;

	put_dvfs_file_struct (objid);
}

void put_dvfs_file(int index, struct file *file)
{
	struct dvfs_file_struct *dvfs_file;
	unsigned long objid = file->f_objid;

	dvfs_file = grab_dvfs_file_struct(objid);
	dvfs_file->count--;

#ifdef CONFIG_KRG_FAF
	check_last_faf_client_close(file, dvfs_file);
#endif

	/* else someone has allocated a new structure during the grab */

	if (dvfs_file->count == 0)
		_kddm_remove_frozen_object (dvfs_file_struct_ctnr, objid);
	else
		put_dvfs_file_struct (objid);
}

/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/

/** Get fresh position value for the given file struct.
 *  @author Renaud Lottiaux
 *
 *  @param file    Struct of the file to get the position value.
 */
loff_t krg_file_pos_read(struct file *file)
{
	struct dvfs_file_struct *dvfs_file;
	loff_t pos;

	dvfs_file = get_dvfs_file_struct (file->f_objid);

	pos = dvfs_file->f_pos;

	put_dvfs_file_struct (file->f_objid);

	return pos;
}

/** Write the new file position in the file container.
 *  @author Renaud Lottiaux
 *
 *  @param file    Struct of the file to write position value.
 */
void krg_file_pos_write(struct file *file, loff_t pos)
{
	struct dvfs_file_struct *dvfs_file;

	dvfs_file = grab_dvfs_file_struct (file->f_objid);

	dvfs_file->f_pos = pos;

	put_dvfs_file_struct (file->f_objid);
}

/** Decrease usage count on a dvfs file struct.
 *  @author Renaud Lottiaux
 *
 *  @param file    Struct of the file to decrease usage counter.
 */
void krg_put_file(struct file *file)
{
	BUG_ON (file->f_objid == 0);

	put_dvfs_file(-1, file);
}

/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/

int dvfs_file_init(void)
{
	init_and_set_unique_id_root (&file_struct_unique_id_root, 1);

	/* Create the DVFS file struct container */

	dvfs_file_struct_ctnr = create_new_kddm_set(
		kddm_def_ns,
		DVFS_FILE_STRUCT_KDDM_ID,
		DVFS_FILE_STRUCT_LINKER,
		KDDM_RR_DEF_OWNER,
		sizeof (struct dvfs_file_struct),
		KDDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(dvfs_file_struct_ctnr))
		OOM;

	return 0;
}

void dvfs_file_finalize (void)
{
}
