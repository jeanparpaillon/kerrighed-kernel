#ifndef CHECKPOINT_TYPES_H
#define CHECKPOINT_TYPES_H

#include <linux/types.h>

#define E_CR_APPBUSY     1000
#define E_CR_PIDBUSY     1001
#define E_CR_TASKDEAD    1002
#define E_CR_BADDATA     1003

#define APP_FROM_PID			1
#define CKPT_W_UNSUPPORTED_FILE		2

struct checkpoint_info
{
	long app_id;

	int flags;

	int chkpt_sn;
	int result;

	int signal;
};

#define GET_RESTART_CMD_PTS 1

struct restart_request
{
	long app_id;
	int chkpt_sn;
	int flags;
	pid_t root_pid;
};

struct app_userdata_request
{
	long app_id;
	int flags;
	__u64 user_data;
};

struct cr_mm_region
{
	pid_t pid;
	unsigned long addr;
	size_t size;

	struct cr_mm_region *next;
};

#endif
