/*
 *  Kerrighed/modules/ipc/mobility.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/sem.h>
#include <linux/unique_id.h>
#include <kddm/kddm.h>
#include <kerrighed/ghost.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include "sem_handler.h"
#include "semundolst_io_linker.h"

extern struct kddm_set *sem_undo_list_kddm_set;

int export_ipc_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	/* IPC namespace sharing is not implemented yet */
	BUG_ON (task->nsproxy->ipc_ns != &init_ipc_ns);

	return 0;
}

int import_ipc_namespace(struct epm_action *action,
			 ghost_t *ghost, struct task_struct *task)
{
	task->nsproxy->ipc_ns = get_ipc_ns(&init_ipc_ns);

	return 0;
}

void unimport_ipc_namespace(struct task_struct *task)
{
	put_ipc_ns(task->nsproxy->ipc_ns);
}


static int cr_export_later_sysv_sem(struct epm_action *action,
				    ghost_t *ghost,
				    struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != EPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	/* if this is not true anymore, it's time to change
	   this implementation ... */
	BUG_ON(sizeof(unique_id_t) != sizeof(long));

	key = (long)(task->sysvsem.undo_list_id);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto err;

	if (task->sysvsem.undo_list_id != UNIQUE_ID_NONE) {
		r = add_to_shared_objects_list(
			&task->application->shared_objects,
			SEMUNDO_LIST, key, 0 /* !is_local */, task, NULL);

		if (r == -ENOKEY) /* the semundo list was already in the list */
			r = 0;
	}
err:
	return r;
}

int export_sysv_sem(struct epm_action *action,
		    ghost_t *ghost, struct task_struct *task)
{
	int r;
	unique_id_t undo_list_id = UNIQUE_ID_NONE;

	BUG_ON(task->sysvsem.undo_list);

	if (action->type == EPM_CHECKPOINT &&
	    action->checkpoint.shared == CR_SAVE_LATER) {
		r = cr_export_later_sysv_sem(action, ghost, task);
		return r;
	}

	/* lazy creation of semundo list:
	   - nothing to do on migration
	   - nothing to do on remote fork if CLONE_SYSVSEM is not set
	   - need to create it if CLONE_SYSVSEM and still not created */
	if (task->sysvsem.undo_list_id == UNIQUE_ID_NONE
	    && action->type == EPM_REMOTE_CLONE
	    && (action->remote_clone.clone_flags & CLONE_SYSVSEM)) {
		r = create_semundo_proc_list(task);
		if (r)
			goto err;

		undo_list_id = UNIQUE_ID_NONE;
	}

	/* does the remote process will use our undo_list ? */
	if (action->type == EPM_MIGRATE
	    || action->type == EPM_CHECKPOINT
	    || (action->type == EPM_REMOTE_CLONE
		&& (action->remote_clone.clone_flags & CLONE_SYSVSEM)))
		undo_list_id = task->sysvsem.undo_list_id;

	r = ghost_write(ghost, &undo_list_id, sizeof(unique_id_t));

err:
	return r;
}

static int cr_link_to_sysv_sem(struct epm_action *action,
			       ghost_t *ghost,
			       struct task_struct *task)
{
	int r;
	long key;
	unique_id_t undo_list_id;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	if ((unique_id_t)key == UNIQUE_ID_NONE) {
		task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	} else {
		undo_list_id = (unique_id_t)get_imported_shared_object(
			&action->restart.app->shared_objects,
			SEMUNDO_LIST, key);

		BUG_ON(undo_list_id == UNIQUE_ID_NONE);
		r = share_existing_semundo_proc_list(task, undo_list_id);
	}
err:
	return r;
}

int import_sysv_sem(struct epm_action *action,
		    ghost_t *ghost, struct task_struct *task)
{
	int r;
	unique_id_t undo_list_id;

	task->sysvsem.undo_list = NULL; /* fake task_struct ... */

	if (action->type == EPM_CHECKPOINT
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_sysv_sem(action, ghost, task);
		return r;
	}

	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
	/*BUG_ON(task->sysvsem.undo_list);*/

	r = ghost_read(ghost, &undo_list_id, sizeof(unique_id_t));
	if (r)
		goto err;

	if (undo_list_id != UNIQUE_ID_NONE) {
		if (action->type == EPM_CHECKPOINT)
			r = create_semundo_proc_list(task);
		else
			r = share_existing_semundo_proc_list(task,
							     undo_list_id);
	}

err:
	return r;
}

void unimport_sysv_sem(struct task_struct *task)
{
	task->sysvsem.undo_list_id = UNIQUE_ID_NONE;
}

static int cr_export_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *task,
				  union export_args *args)
{
	int r;
	r = export_sysv_sem(action, ghost, task);
	return r;
}


static int cr_import_now_sysv_sem(struct epm_action *action, ghost_t *ghost,
				  struct task_struct *fake,
				  void ** returned_data)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_sysv_sem(action, ghost, fake);
	if (r)
		goto err;

	*returned_data = (void*)fake->sysvsem.undo_list_id;
err:
	return r;
}

static int cr_import_complete_sysv_sem(struct task_struct * fake,
				       void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;
	if (undo_list_id != UNIQUE_ID_NONE)
		leave_semundo_proc_list(undo_list_id);

	return 0;
}

static int cr_delete_sysv_sem(struct task_struct * fake, void * _undo_list_id)
{
	unique_id_t undo_list_id = (unique_id_t)_undo_list_id;
	semundo_list_object_t * undo_list;

	undo_list = _kddm_grab_object_no_ft(sem_undo_list_kddm_set,
					    undo_list_id);
	if (undo_list)
		_kddm_remove_frozen_object(sem_undo_list_kddm_set,
					   undo_list_id);
	else
		_kddm_put_object(sem_undo_list_kddm_set,
				 undo_list_id);

	return 0;
}


struct shared_object_operations cr_shared_semundo_ops = {
        .restart_data_size = 0,
        .export_now        = cr_export_now_sysv_sem,
	.import_now        = cr_import_now_sysv_sem,
	.import_complete   = cr_import_complete_sysv_sem,
	.delete            = cr_delete_sysv_sem,
};
