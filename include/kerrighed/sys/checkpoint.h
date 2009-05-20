#ifndef CHECKPOINT_TYPES_H
#define CHECKPOINT_TYPES_H

#include <linux/types.h>

#define E_CR_APPBUSY     1000
#define E_CR_PIDBUSY     1001
#define E_CR_TASKDEAD    1002
#define E_CR_BADDATA     1003

typedef enum {
	FROM_APPID,
	FROM_PID
} type_ckpt_t;

typedef struct checkpoint_info
{
	long app_id;

	type_ckpt_t type;

	int chkpt_sn;
	int result;

	int signal;
} checkpoint_infos_t ;

#define GET_RESTART_CMD_PTS 1

typedef struct restart_request
{
	long app_id;
	int chkpt_sn;
	int flags;
} restart_request_t;

typedef struct app_userdata_request
{
	long app_id;
	type_ckpt_t type;
	__u64 user_data;
} app_userdata_request_t;

#endif
