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
	struct restart_request restart_req;
	pid_t root_pid;

	if (copy_from_user(&restart_req, arg, sizeof(restart_req)))
		return -EFAULT;

	res = sys_app_restart(&restart_req, &root_pid);

	/*
	 * in case of success, we replace the req.app_id by the application
	 * root process id.
	 */
	if (!res) {
		res = root_pid;

		if (copy_to_user(arg, &restart_req, sizeof(restart_req)))
			return -EFAULT;
	}

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

	return 0;

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

	procfs_deltree(proc_epm);
}
