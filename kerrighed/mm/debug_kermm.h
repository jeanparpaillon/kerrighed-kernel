#ifndef __DEBUG_KERMM_H__

#define __DEBUG_KERMM_H__

#include <kerrighed/debug.h>
#include <kerrighed/debug_tools2.h>

#ifndef CONFIG_KRG_DEBUG
#	define INIT_MM_DEBUG() do {} while (0)
#else
#       define INIT_MM_DEBUG()   			\
	do {						\
		debug_define("mm", 0);	        	\
		DEBUG_MASK("mm", "io_linker");		\
		DEBUG_MASK("mm", "int_linker");		\
		DEBUG_MASK("mm", "mm_struct");          \
		DEBUG_MASK("mm", "vma_struct");         \
		DEBUG_MASK("mm", "pg_table");           \
		DEBUG_MASK("mm", "mobility");		\
		DEBUG_MASK("mm", "injection");		\
	} while (0)
#endif

#ifdef DEBUG
#undef DEBUG
#endif

#ifndef CONFIG_KRG_DEBUG
#	define DEBUG(mask, level, setid, objid, format, args...) do {} while(0)
#else
void krgmm_debug(const char *format, ...)
	__attribute__ ((format (printf, 1, 2)));
#	define DEBUG(mask, level, setid, objid, format, args...)        \
        do {                                                            \
	if (match_debug("mm", mask, level)) {			        \
		if ((setid == 0) && (objid == 0))			\
			krgmm_debug("MM - %7d - %30.30s - " format,	\
				    current->pid, __PRETTY_FUNCTION__,	\
				    ## args);				\
		else							\
			krgmm_debug("MM - %7d - %30.30s (%ld;%ld) "	\
				    format,				\
				    current->pid, __PRETTY_FUNCTION__,	\
				    setid, objid, ## args);		\
	}} while (0)
#endif

#endif // __DEBUG_KERMM_H__
