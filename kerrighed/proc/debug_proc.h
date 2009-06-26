#ifndef __DEBUG_PROC_H__
#define __DEBUG_PROC_H__

#include <kerrighed/pid.h>
#include <kerrighed/debug.h>

#define DEBUG_GROUP	"proc"

#define DBG_MODULE	"module"
#define DBG_RSYSCALL	"rsyscall"
#define DBG_TASK_KDDM	"task_kddm"
#define DBG_EXIT	"exit"
#define DBG_CRED_MOB	"cred_mobility"

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define DEBUG(mask, level, format, args...) do {} while(0)
#else
#	define DEBUG(mask, level, format, args...)			\
	pr_debug(DEBUG_NORMAL DEBUG_COLOR(GREEN)			\
		 "krg" DEBUG_GROUP "_" mask #level			\
		 " %s %d/%d(%s): " format,				\
		 __PRETTY_FUNCTION__,					\
		 task_pid_knr(current), current->pid, current->comm,	\
		 ## args);
#endif

#endif /* __DEBUG_PROC_H__ */
