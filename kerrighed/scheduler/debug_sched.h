#ifndef __DEBUG_SCHED_H__
#define __DEBUG_SCHED_H__

#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

#define DEBUG_GROUP	"scheduler"

#define DBG_GLOBAL_LOCK		"global_lock"
#define DBG_GLOBAL_CONFIG	"global_config"
#define DBG_POLICY		"policy"
#define DBG_PIPE		"pipe"
#define DBG_REMOTE_PIPE		"remote_pipe"
#define DBG_PROBE		"probe"
#define DBG_PORT		"port"
#define DBG_PROCESS_SET		"process set"

static inline struct dentry *init_scheduler_debug(void)
{
#ifndef CONFIG_KRG_DEBUG
	return NULL;
#else
	struct dentry *d = debug_define(DEBUG_GROUP, 0);

	DEBUG_MASK(DEBUG_GROUP, DBG_GLOBAL_LOCK);
	DEBUG_MASK(DEBUG_GROUP, DBG_GLOBAL_CONFIG);
	DEBUG_MASK(DEBUG_GROUP, DBG_POLICY);
	DEBUG_MASK(DEBUG_GROUP, DBG_PIPE);
	DEBUG_MASK(DEBUG_GROUP, DBG_REMOTE_PIPE);
	DEBUG_MASK(DEBUG_GROUP, DBG_PROBE);
	DEBUG_MASK(DEBUG_GROUP, DBG_PORT);
	DEBUG_MASK(DEBUG_GROUP, DBG_PROCESS_SET);

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
		       "%s %d: " format,				\
		       __PRETTY_FUNCTION__, current->pid, ## args);	\
	}
#endif

#endif	/* __DEBUG_SCHED_H__ */
