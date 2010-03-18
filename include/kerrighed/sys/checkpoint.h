#include <linux/types.h>

#ifndef CHECKPOINT_TYPES_H
#define CHECKPOINT_TYPES_H

#define E_CR_APPBUSY     1000
#define E_CR_PIDBUSY     1001
#define E_CR_TASKDEAD    1002
#define E_CR_BADDATA     1003

#define APP_FROM_PID		1
#define CKPT_W_UNSUPPORTED_FILE	2

#define APP_REPLACE_PGRP_SID	1

struct checkpoint_info
{
	long app_id;

	int flags;

	int chkpt_sn;
	int result;

	int signal;
};

struct cr_subst_file
{
	int fd;
	char *file_id;
};

struct cr_subst_files_array
{
	unsigned int nr;
	struct cr_subst_file *files;
};

struct restart_request
{
	long app_id;
	int chkpt_sn;
	int flags;
	pid_t root_pid;

	struct cr_subst_files_array substitution;
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
