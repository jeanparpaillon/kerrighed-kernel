/** IPC snapshot API
 *  @file ipc_checkpoint.c
 *
 *  @author Matthieu Fertré
 */

#define MODULE_NAME "IPC checkpoint"
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <kerrighed/ghost.h>
#include <kerrighed/file_ghost.h>
#include "krgipc_mobility.h"
#include "ipc_checkpoint.h"

int sys_msgq_checkpoint(int msqid, int fd)
{
	int r;

	r = __sys_msgq_checkpoint(msqid, fd);

	return r;
}

int sys_msgq_restart(int fd)
{
	int r;
	ghost_fs_t oldfs;
	ghost_t *ghost;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost_from_fd(GHOST_READ, fd);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	r = import_full_sysv_msgq(ghost);

	ghost_close(ghost);
exit:
	unset_ghost_fs(&oldfs);
	return r;
}

int sys_sem_checkpoint(int semid, int fd)
{
	int r;
	ghost_fs_t oldfs;
	ghost_t *ghost;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost_from_fd(GHOST_WRITE, fd);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	r = export_full_sysv_sem(ghost, semid);

	ghost_close(ghost);
exit:
	unset_ghost_fs(&oldfs);
	return r;
}

int sys_sem_restart(int fd)
{
	int r;
	ghost_fs_t oldfs;
	ghost_t *ghost;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost_from_fd(GHOST_READ, fd);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	r = import_full_sysv_sem(ghost);

	ghost_close(ghost);
exit:
	unset_ghost_fs(&oldfs);
	return r;
}

int sys_shm_checkpoint(int shmid, int fd)
{
	int r;
	ghost_fs_t oldfs;
	ghost_t *ghost;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost_from_fd(GHOST_WRITE, fd);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	r = export_full_sysv_shm(ghost, shmid);

	ghost_close(ghost);
exit:
	unset_ghost_fs(&oldfs);
	return r;
}

int sys_shm_restart(int fd)
{
	int r;
	ghost_fs_t oldfs;
	ghost_t *ghost;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost_from_fd(GHOST_READ, fd);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit;
	}

	r = import_full_sysv_shm(ghost);

	ghost_close(ghost);
exit:
	unset_ghost_fs(&oldfs);
	return r;
}


