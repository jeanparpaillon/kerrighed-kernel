#ifndef __DEBUG_X86_64_H__
#define __DEBUG_X86_64_H__

#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

#define DBG_GHOST	"ghost"

static inline struct dentry * init_arch_x86_64_debug(void)
{
#ifndef CONFIG_KRG_DEBUG
	return NULL;
#else
	struct dentry *d = debug_define("arch_x86_64", 0);

	DEBUG_MASK("arch_x86_64", DBG_GHOST);

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
	if (match_debug("arch_x86_64", mask, level)) {			\
		printk(KERN_DEBUG DEBUG_NORMAL				\
		       MODULE_NAME " (%s) %d: "	format,			\
		       __PRETTY_FUNCTION__, current->pid, ## args);	\
	}
#endif

#endif /* __DEBUG_X86_64_H__ */
