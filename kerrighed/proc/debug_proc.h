#ifndef __DEBUG_PROC_H__
#define __DEBUG_PROC_H__

#include <kerrighed/pid.h>
#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

#define DEBUG_GROUP	"proc"

#define DBG_MODULE	"module"
#define DBG_RSYSCALL	"rsyscall"
#define DBG_TASK_KDDM	"task_kddm"
#define DBG_EXIT	"exit"
#define DBG_CRED_MOB	"cred_mobility"

static inline struct dentry *init_proc_debug(void)
{
#ifndef CONFIG_KRG_DEBUG
	return NULL;
#else
	struct dentry *d = debug_define(DEBUG_GROUP, 0);

	DEBUG_MASK(DEBUG_GROUP, DBG_MODULE);
	DEBUG_MASK(DEBUG_GROUP, DBG_RSYSCALL);
	DEBUG_MASK(DEBUG_GROUP, DBG_TASK_KDDM);
	DEBUG_MASK(DEBUG_GROUP, DBG_EXIT);
	DEBUG_MASK(DEBUG_GROUP, DBG_CRED_MOB);

	return d;
#endif
}

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define DEBUG(mask, level, format, args...) do {} while(0)
#else
#define MAX_DEBUG_LEVEL 5
#define CURRENT_SIZE 32
static void fill_current_pid(char *buf)
{
	snprintf(buf, CURRENT_SIZE, "%d", task_pid_knr(current));
}
static void fill_current_full(char *buf)
{
	snprintf(buf, CURRENT_SIZE, "%d(%s)", task_pid_knr(current), current->comm);
}
static void __attribute__((unused)) (*fill_current_array[MAX_DEBUG_LEVEL + 1])(char *) = {
	[0] = fill_current_pid,
	[1] = fill_current_full,
	[2] = fill_current_full,
	[3] = fill_current_full,
	[4] = fill_current_full,
	[5] = fill_current_full,
};
#	define DEBUG(mask, level, format, args...)			\
	if (match_debug(DEBUG_GROUP, mask, level)) {			\
		char current_string[CURRENT_SIZE];			\
		int index = level < MAX_DEBUG_LEVEL ? level : MAX_DEBUG_LEVEL; \
		fill_current_array[index](current_string);		\
		printk(KERN_DEBUG DEBUG_NORMAL DEBUG_COLOR(GREEN)	\
		       MODULE_NAME " (%s) %s: " format,			\
		       __PRETTY_FUNCTION__, current_string, ## args);	\
	}
#endif

#endif /* __DEBUG_PROC_H__ */
