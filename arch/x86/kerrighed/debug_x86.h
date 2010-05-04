#ifndef __KRG_DEBUG_X86_H__
#define __KRG_DEBUG_X86_H__

#ifdef CONFIG_KRG_DEBUG

#include <kerrighed/pid.h>
#include <kerrighed/debug.h>

#define DEBUG_GROUP	"arch"
#define DBG_GHOST	"ghost"

#ifdef DEBUG
#undef DEBUG
#endif

#define DEBUG(mask, level, format, args...)				\
	pr_debug(DEBUG_NORMAL "krg" DEBUG_GROUP "_" mask #level		\
		 " %s %d/%d(%s): " format,				\
		 __PRETTY_FUNCTION__,					\
		 task_pid_knr(current), current->pid, current->comm,	\
		 ## args);

#else /* !CONFIG_KRG_DEBUG */

#define DEBUG(mask, level, format, args...) do {} while(0)

#endif /* !CONFIG_KRG_DEBUG */

#endif /* __KRG_DEBUG_X86_H__ */
