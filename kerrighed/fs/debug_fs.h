#ifndef __DEBUG_DVFS_H__

#define __DEBUG_DVFS_H__

#include <kerrighed/debug_tools2.h>
#include <kerrighed/debug.h>
#include <kerrighed/krginit.h>
#ifdef CONFIG_KRG_FAF
#include "faf/faf_internal.h"

struct dvfs_log {
       pid_t current_pid;
       pid_t task_pid;
       struct file *file;
       unsigned long fd;
       unsigned long objid;
       unsigned long fct_addr;
       unsigned long data;
       unsigned long data2;
       int dbg_id;
       struct dvfs_log *next;
       char filename[1];
};

enum {
	DVFS_LOG_ENTER,
	DVFS_LOG_ENTER_PUT_DVFS,
	DVFS_LOG_ENTER_EXPORT_VMA,
	DVFS_LOG_ENTER_IMPORT_VMA,
	DVFS_LOG_ENTER_EXPORT_FILE,
	DVFS_LOG_ENTER_IMPORT_FILE,
	DVFS_LOG_EXIT,
	DVFS_LOG_EXIT_GET_DVFS,
	DVFS_LOG_EXIT_EXPORT_FILE,
	DVFS_LOG_EXIT_IMPORT_FILE,
	DVFS_LOG_EXIT_CREATE_OBJID,
	DVFS_LOG_IMPORT_INFO,
	DVFS_LOG_EXPORT_REG_FILE,

	FAF_LOG_ENTER,
	FAF_LOG_EXIT,
	FAF_LOG_SETUP_FILE,
	FAF_LOG_CLOSE_SRV_FILE,
	FAF_LOG_EXPORT_FAF_FILE,
	FAF_LOG_ACCEPT_DONE,
};

#define DVFS_LOG_PACKFD(a,b,c) ((((a)&0xFF)<<24) | (((b)&0xFFF)<<12) | ((c)&0xFFF))

#define DVFS_LOG_UNPACKFD1(log) (((log->fd)>>24) & 0xFF)
#define DVFS_LOG_UNPACKFD2(log) (((log->fd)>>12) & 0xFFF)
#define DVFS_LOG_UNPACKFD3(log) (((log->fd)) & 0xFFF)


static inline int faf_srv_fd(struct file *file)
{
	faf_client_data_t *data;

	if (!file)
		return -1;

	data = file->private_data;
	if (file->f_flags & O_FAF_SRV)
		return file->f_faf_srv_index;
	if ((file->f_flags & O_FAF_CLT) && data)
		return data->server_fd;
	return -1;
}

static inline int faf_srv_id(struct file *file)
{
	faf_client_data_t *data;

	if (!file)
		return -1;
	data = file->private_data;
	if (file->f_flags & O_FAF_SRV)
		return kerrighed_node_id;
	if ((file->f_flags & O_FAF_CLT) && data)
		return data->server_id;
	return -1;
}

static inline unsigned long dvfs_objid(struct file *file)
{
	if (!file)
		return -1UL;
	return file->f_objid;
}
#endif // CONFIG_KRG_FAF

void dvfs_save_log(unsigned long eip, const char *module, const char* mask,
		   int level, int fd, int server_id, int server_fd,
		   unsigned long objid, struct task_struct *tsk,
		   struct file *file, int dbg_id, unsigned long data);

void init_dvfs_debug(void);

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#       define DEBUG(mask, level, fd, server_id, server_fd, file_id, tsk, file,\
		     dbg_id, data) do {} while(0)
#else
#	define DEBUG(mask, level, fd, server_id, server_fd, file_id, tsk, file, dbg_id, data)\
	dvfs_save_log(_THIS_IP_, "dvfs", mask, level, fd, server_id, server_fd, file_id, tsk, file, dbg_id, (unsigned long)data)
#endif

#endif // __DEBUG_DVFS_H__
