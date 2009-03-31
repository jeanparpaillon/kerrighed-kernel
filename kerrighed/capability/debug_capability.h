#ifndef __DEBUG_CAPABILITY_H__
#define __DEBUG_CAPABILITY_H__

#include <kerrighed/debug.h>

#define CAP_DEBUG_LEVEL 0

#define DBG_CAP		(1 << 0)

#define CAP_DEBUG_MASK 0	| \
		       0

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define DEBUG(type, level, format, args...) do {} while(0)
#else
#	define DEBUG(type, level, format, args...)			\
do {									\
	if ((CAP_DEBUG_LEVEL >= level) &&				\
	    (type & (CAP_DEBUG_MASK))) {				\
		printk(KERN_DEBUG DEBUG_NORMAL				\
		       MODULE_NAME " (%s) %d: " format,			\
		       __PRETTY_FUNCTION__, current->pid, ## args);	\
	}								\
} while (0)
#endif

#endif /* __DEBUG_CAPABILITY_H__ */
