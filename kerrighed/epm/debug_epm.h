#ifndef __DEBUG_EPM_H__
#define __DEBUG_EPM_H__

#include <kerrighed/pid.h>
#include <kerrighed/debug.h>

#define DEBUG_GROUP	"epm"

#define DBG_MODULE	"module"
#define DBG_APPLICATION	"application"
#define DBG_APP_CKPT	"app_ckpt"
#define DBG_CKPT_API	"ckpt_api"
#define DBG_CKPT	"ckpt"
#define DBG_FORK_DELAY	"fork_delay"
#define DBG_GHOST_API	"ghost_api"
#define DBG_GHOST_MNGMT "ghost_mngmt"
#define DBG_SIGHAND	"sighand"
#define DBG_SIGNAL	"signal"
#define DBG_PID		"pid"
#define DBG_CHILDREN	"children"
#define DBG_G_SIGNAL	"g_signal"
#define DBG_G_TASK	"g_task"
#define DBG_MIGRATION	"migration"
#define DBG_MIGR_API	"migr_api"
#define DBG_RCLONE	"rclone"
#define DBG_PROCFS	"procfs"
#define DBG_RESTART	"restart"
#define DBG_THREAD	"thread"
#define DBG_PTRACE	"ptrace"
#define DBG_ACTION	"action"

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define DEBUG(mask, level, format, args...) do {} while(0)
#else
#	define DEBUG(mask, level, format, args...)			\
	pr_debug(DEBUG_NORMAL "krg" DEBUG_GROUP "_" mask #level		\
		 " %s %d/%d(%s): " format,				\
		 __PRETTY_FUNCTION__,					\
		 task_pid_knr(current), current->pid, current->comm,	\
		 ## args);
#endif

#endif /* __DEBUG_EPM_H__ */
