#include <linux/types.h>

#ifndef CHECKPOINT_TYPES_H
#define CHECKPOINT_TYPES_H

#define E_CR_APPBUSY     1000
#define E_CR_PIDBUSY     1001
#define E_CR_TASKDEAD    1002
#define E_CR_BADDATA     1003

#define APP_FROM_PID		1
#define CKPT_W_UNSUPPORTED_FILE	2

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
	pid_t root_pid;
	int flags;

	struct cstr storage_dir;

	struct cr_subst_files_array substitution;
};

struct app_userdata_request
{
	long app_id;
	int flags;
	__u64 user_data;
};

#endif
