#ifndef __KRG_DEBUG_X86_H__
#define __KRG_DEBUG_X86_H__

#ifdef CONFIG_KRG_DEBUG

#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

#define DEBUG_GROUP	"arch"
#define DBG_GHOST	"ghost"

static inline struct dentry *init_arch_debug(void)
{
	struct dentry *d = debug_define(DEBUG_GROUP, 0);

	DEBUG_MASK(DEBUG_GROUP, DBG_GHOST);

	return d;
}

#ifdef DEBUG
#undef DEBUG
#endif

#define DEBUG(mask, level, format, args...)				\
	if (match_debug(DEBUG_GROUP, mask, level)) {			\
		printk(KERN_DEBUG DEBUG_NORMAL				\
		       MODULE_NAME " (%s) %d: "	format,			\
		       __PRETTY_FUNCTION__, current->pid, ## args);	\
	}

#else /* !CONFIG_KRG_DEBUG */

#define DEBUG(mask, level, format, args...) do {} while(0)

#endif /* !CONFIG_KRG_DEBUG */

#endif /* __KRG_DEBUG_X86_H__ */
