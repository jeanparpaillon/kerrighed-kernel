/*
 *  kerrighed/epm/procfs.c
 *
 *  Copyright (C) 1999-2006 INRIA, Universite de Rennes 1, EDF
 */

/**
 *  /proc manager
 *
 *  @author Geoffroy Vallée.
 */

#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <kerrighed/krg_syscalls.h>
#include <kerrighed/krg_services.h>
#include <kerrighed/procfs.h>
#include <kerrighed/migration.h>
#include "migration.h"
#include "application/application_cr_api.h"

static struct proc_dir_entry *proc_epm = NULL;

/**
 *  /proc function call to migrate a task
 *  @author Geoffroy Vallée
 *
 *  @param arg	Migration arguments from user space.
 */
static int proc_migrate_process(void __user *arg)
{
	migration_infos_t migration_info;

	if (copy_from_user(&migration_info, arg, sizeof(migration_info)))
		return -EFAULT;

	return sys_migrate_process(migration_info.process_to_migrate,
				   migration_info.destination_node_id);
}

/**
 *  /proc function call to migrate a thread
 *  @author Geoffroy Vallée
 *
 *  @param arg	Migration arguments from user space.
 */
static int proc_migrate_thread(void __user *arg)
{
	migration_infos_t migration_info;

	if (copy_from_user(&migration_info, arg, sizeof(migration_info)))
		return -EFAULT;

	return sys_migrate_thread(migration_info.thread_to_migrate,
				  migration_info.destination_node_id);
}

/**
 *  /proc function call to freeze an application.
 *  @author Matthieu Fertré
 */
static int proc_app_freeze(void __user *arg)
{
	struct checkpoint_info ckpt_info;

	if (copy_from_user(&ckpt_info, arg, sizeof(ckpt_info)))
		return -EFAULT;

	return sys_app_freeze(&ckpt_info);
}

/**
 *  /proc function call to unfreeze an application.
 *  @author Matthieu Fertré
 */
static int proc_app_unfreeze(void __user *arg)
{
	struct checkpoint_info ckpt_info;

	if (copy_from_user(&ckpt_info, arg, sizeof(ckpt_info)))
		return -EFAULT;

	return sys_app_unfreeze(&ckpt_info);
}

static int copy_user_array(void **array, const void __user *from, int len)
{
	int res = 0;

	*array = kmalloc(len, GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	if (copy_from_user(*array, from, len)) {
		kfree(*array);
		res = -EFAULT;
	}

	return res;
}

/**
 *  /proc function call to checkpoint an application.
 *  @author Matthieu Fertré
 *
 *  @param pid	Pid of one of the application processes
 */
static int proc_app_chkpt(void __user *arg)
{
	int res;
	struct checkpoint_info ckpt_info;

	if (copy_from_user(&ckpt_info, arg, sizeof(ckpt_info)))
		return -EFAULT;

	res = sys_app_chkpt(&ckpt_info);

	if (copy_to_user(arg, &ckpt_info, sizeof(ckpt_info)))
		return -EFAULT;

	return res;
}

/**
 *  /proc function call to restart a checkpointed application.
 *  @author Matthieu Fertré
 *
 *  @param pid		Pid of one of the application processes
 *  @param version	Version of checkpoint
 */
static int proc_app_restart(void __user *arg)
{
	int res;
	unsigned int i = 0;
	struct restart_request restart_req;

	size_t file_str_len;
	struct cr_subst_file *files = NULL;

	if (copy_from_user(&restart_req, arg, sizeof(restart_req)))
		return -EFAULT;

	/* let's say that a user can not substitute more that 256 files */
	if (restart_req.substitution.nr > 256) {
		res = -E2BIG;
		goto error;
	}

	/* first basic check about files substitution args */
	if (!restart_req.substitution.nr) {
		if (!restart_req.substitution.files)
			goto call_restart;

		res = -EINVAL;
		goto error;
	}

	/* get the list of files to replace */
	res = copy_user_array((void**)&files,
			      restart_req.substitution.files,
			      restart_req.substitution.nr *
			      sizeof(struct cr_subst_file));
	if (res)
		goto error;

	file_str_len = sizeof(kerrighed_node_t)*2 + sizeof(unsigned long)*2;

	for (i = 0; i < restart_req.substitution.nr; i++) {

		if (strlen(restart_req.substitution.files[i].file_id)
		    == file_str_len)
			res = copy_user_array(
				(void**)&files[i].file_id,
				restart_req.substitution.files[i].file_id,
				file_str_len + 1);
		else
			res = -EINVAL;

		if (res) {
			files[i].file_id = NULL;
			goto err_free_files;
		}
	}

	restart_req.substitution.files = files;

call_restart:
	/* call the restart */
	res = sys_app_restart(&restart_req);
	if (res)
		goto err_free_files;

	if (copy_to_user(arg, &restart_req, sizeof(restart_req)))
		res = -EFAULT;

err_free_files:
	for (i = 0; i < restart_req.substitution.nr; i++) {
		if (!files[i].file_id)
			break;

		kfree(files[i].file_id);
	}
error:
	return res;
}

static int proc_app_set_userdata(void __user *arg)
{
	int res;
	__u64 data;

	if (copy_from_user(&data, arg, sizeof(data)))
		return -EFAULT;

	res = sys_app_set_userdata(data);

	return res;
}

static int proc_app_get_userdata(void __user *arg)
{
	int res;
	struct app_userdata_request data_req;

	if (copy_from_user(&data_req, arg, sizeof(data_req)))
		return -EFAULT;

	res = sys_app_get_userdata(&data_req);

	if (copy_to_user(arg, &data_req, sizeof(data_req)))
		return -EFAULT;

	return res;
}

static int proc_app_cr_disable(void __user *arg)
{
	return sys_app_cr_disable();
}

static int proc_app_cr_enable(void __user *arg)
{
	return sys_app_cr_enable();
}

static int proc_app_cr_exclude(void __user *arg)
{
	struct cr_mm_region *first, *element, *next;
	int r;

	first = kzalloc(sizeof(struct cr_mm_region*), GFP_KERNEL);
	if (!first)
		return -ENOMEM;

	if (copy_from_user(first, arg, sizeof(struct cr_mm_region))) {
		r = -EFAULT;
		goto error;
	}

	element = first;
	while (element->next) {

		element->next = NULL;

		next = kzalloc(sizeof(struct cr_mm_region*), GFP_KERNEL);
		if (!next) {
			r = -ENOMEM;
			goto error;
		}

		element->next = next;

		if (copy_from_user(next, arg, sizeof(struct cr_mm_region))) {
			r = -EFAULT;
			next->next = NULL;
			goto error;
		}

		element = next;
	}

	r = sys_app_cr_exclude(first);

error:
	element = first;
	while (element) {
		next = element->next;
		kfree(element);
		element = next;
	}

	return r;
}

int epm_procfs_start(void)
{
	int r;
	int err = -EINVAL;

	/* /proc/kerrighed/epm */

	proc_epm = create_proc_entry("epm", S_IFDIR | 0755, proc_kerrighed);
	if (!proc_epm)
		return -ENOMEM;

	r = register_proc_service(KSYS_PROCESS_MIGRATION, proc_migrate_process);
	if (r)
		goto err;

	r = register_proc_service(KSYS_THREAD_MIGRATION, proc_migrate_thread);
	if (r)
		goto unreg_migrate_process;

	r = register_proc_service(KSYS_APP_FREEZE, proc_app_freeze);
	if (r)
		goto unreg_migrate_thread;

	r = register_proc_service(KSYS_APP_UNFREEZE, proc_app_unfreeze);
	if (r)
		goto unreg_app_freeze;

	r = register_proc_service(KSYS_APP_CHKPT, proc_app_chkpt);
	if (r)
		goto unreg_app_unfreeze;

	r = register_proc_service(KSYS_APP_RESTART, proc_app_restart);
	if (r)
		goto unreg_app_chkpt;

	r = register_proc_service(KSYS_APP_SET_USERDATA, proc_app_set_userdata);
	if (r)
		goto unreg_app_restart;

	r = register_proc_service(KSYS_APP_GET_USERDATA, proc_app_get_userdata);
	if (r)
		goto unreg_app_set_userdata;

	r = register_proc_service(KSYS_APP_CR_DISABLE, proc_app_cr_disable);
	if (r)
		goto unreg_app_get_userdata;

	r = register_proc_service(KSYS_APP_CR_ENABLE, proc_app_cr_enable);
	if (r)
		goto unreg_app_cr_disable;

	r = register_proc_service(KSYS_APP_CR_EXCLUDE, proc_app_cr_exclude);
	if (r)
		goto unreg_app_cr_enable;

	return 0;

unreg_app_cr_enable:
	unregister_proc_service(KSYS_APP_CR_ENABLE);
unreg_app_cr_disable:
	unregister_proc_service(KSYS_APP_CR_DISABLE);
unreg_app_get_userdata:
	unregister_proc_service(KSYS_APP_GET_USERDATA);
unreg_app_set_userdata:
	unregister_proc_service(KSYS_APP_SET_USERDATA);
unreg_app_restart:
	unregister_proc_service(KSYS_APP_RESTART);
unreg_app_chkpt:
	unregister_proc_service(KSYS_APP_CHKPT);
unreg_app_unfreeze:
	unregister_proc_service(KSYS_APP_UNFREEZE);
unreg_app_freeze:
	unregister_proc_service(KSYS_APP_FREEZE);
unreg_migrate_thread:
	unregister_proc_service(KSYS_THREAD_MIGRATION);
unreg_migrate_process:
	unregister_proc_service(KSYS_PROCESS_MIGRATION);
err:
	return err;
}

void epm_procfs_exit(void)
{
	unregister_proc_service(KSYS_PROCESS_MIGRATION);
	unregister_proc_service(KSYS_THREAD_MIGRATION);
	unregister_proc_service(KSYS_APP_FREEZE);
	unregister_proc_service(KSYS_APP_UNFREEZE);
	unregister_proc_service(KSYS_APP_CHKPT);
	unregister_proc_service(KSYS_APP_RESTART);
	unregister_proc_service(KSYS_APP_SET_USERDATA);
	unregister_proc_service(KSYS_APP_GET_USERDATA);
	unregister_proc_service(KSYS_APP_CR_DISABLE);
	unregister_proc_service(KSYS_APP_CR_ENABLE);
	unregister_proc_service(KSYS_APP_CR_EXCLUDE);

	procfs_deltree(proc_epm);
}
