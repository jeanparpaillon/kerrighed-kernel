#ifndef CHECKPOINT_TYPES_H
#define CHECKPOINT_TYPES_H

#include <linux/types.h>

#define E_CR_APPBUSY     1000
#define E_CR_PIDBUSY     1001
#define E_CR_TASKDEAD    1002
#define E_CR_BADDATA     1003

#define APP_FROM_PID			1
#define CKPT_W_UNSUPPORTED_FILE		2

struct cstr
{
	size_t len; /* including the final \0 */
	const char *path;
};

struct checkpoint_info
{
	long app_id;
	int flags;

	int chkpt_sn;
	int result;

	int signal;

	struct cstr storage_dir;
};

#define GET_RESTART_CMD_PTS 1

struct restart_request
{
	long app_id;
	pid_t root_pid;
	int flags;

	struct cstr storage_dir;
};

struct app_userdata_request
{
	long app_id;
	int flags;
	__u64 user_data;
};

#endif
