#ifndef __DEBUG_EPM_H__
#define __DEBUG_EPM_H__

#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

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

static inline struct dentry *init_epm_debug(void)
{
#ifndef CONFIG_KRG_DEBUG
	return NULL;
#else
	struct dentry *d = debug_define(DEBUG_GROUP, 0);

	DEBUG_MASK(DEBUG_GROUP, DBG_MODULE);
	DEBUG_MASK(DEBUG_GROUP, DBG_APPLICATION);
	DEBUG_MASK(DEBUG_GROUP, DBG_APP_CKPT);
	DEBUG_MASK(DEBUG_GROUP, DBG_CKPT_API);
	DEBUG_MASK(DEBUG_GROUP, DBG_CKPT);
	DEBUG_MASK(DEBUG_GROUP, DBG_FORK_DELAY);
	DEBUG_MASK(DEBUG_GROUP, DBG_GHOST_API);
	DEBUG_MASK(DEBUG_GROUP, DBG_GHOST_MNGMT);
	DEBUG_MASK(DEBUG_GROUP, DBG_SIGHAND);
	DEBUG_MASK(DEBUG_GROUP, DBG_SIGNAL);
	DEBUG_MASK(DEBUG_GROUP, DBG_PID);
	DEBUG_MASK(DEBUG_GROUP, DBG_CHILDREN);
	DEBUG_MASK(DEBUG_GROUP, DBG_G_SIGNAL);
	DEBUG_MASK(DEBUG_GROUP, DBG_G_TASK);
	DEBUG_MASK(DEBUG_GROUP, DBG_MIGRATION);
	DEBUG_MASK(DEBUG_GROUP, DBG_MIGR_API);
	DEBUG_MASK(DEBUG_GROUP, DBG_RCLONE);
	DEBUG_MASK(DEBUG_GROUP, DBG_PROCFS);
	DEBUG_MASK(DEBUG_GROUP, DBG_RESTART);
	DEBUG_MASK(DEBUG_GROUP, DBG_THREAD);
	DEBUG_MASK(DEBUG_GROUP, DBG_PTRACE);
	DEBUG_MASK(DEBUG_GROUP, DBG_ACTION);

	return d;
#endif
}

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define DEBUG(mask, level, format, args...) do {} while(0)
#else
#	define DEBUG(mask, level, format, args...)			\
	if (match_debug(DEBUG_GROUP, mask, level)) {			\
		printk(KERN_DEBUG DEBUG_NORMAL				\
		       MODULE_NAME " (%s) %d: " format,			\
		       __PRETTY_FUNCTION__, current->pid, ## args);	\
	}
#endif

#endif /* __DEBUG_EPM_H__ */
