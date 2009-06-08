#ifndef __KRG_DEBUG__
#define __KRG_DEBUG__

#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/hardirq.h>
#include <kerrighed/debug_color.h>

//#define NO_PANIC
//#define NO_WARNING

#ifdef DEBUG_THIS_MODULE

#ifdef DEBUG
#undef DEBUG
#endif

#ifdef WARNING
#undef WARNING
#endif

#ifdef PANIC
#undef PANIC
#endif

#define __DEBUG(DEBUG_LEVEL, level, format, args...) do { \
    if (DEBUG_LEVEL>=level) \
      { \
	if (current->krg_task) { \
	  printk ("(%s) - (%d.%d(%d)) : ", __PRETTY_FUNCTION__,\
		  current->tgid, current->krg_task->tid, current->pid) ; \
	  } \
	else \
	  printk ("(%s) : ", __PRETTY_FUNCTION__) ;\
	printk (format, ## args) ; \
      } \
  } while (0)

#ifdef SYNC
#define DEBUG(level, format, args...) __DEBUG(SYNC_DEBUG_LEVEL, level, format, ## args)
#endif

#if defined(LEGOLAS) || defined(GIMLI) || defined(PALANTIR) || defined(PALANTIR_INET) || defined(PALANTIR_UNIX) || defined(PALANTIR_PIPE) || defined(GLOIN) || defined(GLOIN_NETDEVICE) || defined(GLOIN_MYRINET_GM) || defined(NAZGUL) || defined(PROCFS)

#  define DEBUG_NONE				 (0)
#  define DEBUG_ALL          (~0)

#  if defined(DEBUG_LEVEL)
#    define DEBUG(type, value, format, args...) {			\
        if(__krg_panic__) {						\
          if(!in_interrupt()) { while(1) schedule(); } else { BUG(); }; \
        } else {							\
          if((type & DEBUG_MASQ)&&(value<=DEBUG_LEVEL)) {		\
                printk(KERN_DEBUG DEBUG_NORMAL				\
		       "(%d/%d-%d)%s: "					\
		       format,						\
		       current->pid, current->tgid, smp_processor_id(),	\
		       __PRETTY_FUNCTION__,				\
		       ##args) ;					\
           };								\
        };								\
     }
#  elif defined(DEBUG_LEVEL_GLOBAL)
#    define DEBUG(type, value, format, args...) {			\
        if(__krg_panic__) {						\
          if(!in_interrupt()) { while(1) schedule(); } else { BUG(); }; \
        } else {							\
	  if((type & DEBUG_MASQ)&&(value<=DEBUG_LEVEL_GLOBAL)) {	\
	    printk(KERN_DEBUG DEBUG_NORMAL				\
		   "(%d/%d-%d)%s: "					\
		   format,						\
		   current->pid, current->tgid, smp_processor_id(),	\
		   __PRETTY_FUNCTION__,					\
		   ##args) ;						\
	  };								\
        };								\
     }
#  else
#    define DEBUG(type, value, format, args...) {			\
	if(type & DEBUG_MASQ) {						\
		printk("(%d/%d)%s: "					\
		       format,						\
		       current->pid, current->tgid, __PRETTY_FUNCTION__	\
		       ##args);						\
	};								\
     }
#  endif

#ifdef DEBUG_PORT_FILTERED_ACTIVE
#define DEBUG_PORT_FILTERED(channel, type, level, format, args...) \
  if (((channel)==observed_channel)||((channel)==observed_channel2)||(observed_channel==-1)) \
    DEBUG(type,level,format,##args)
#else
#define DEBUG_PORT_FILTERED(channel, type, level, format, args...) \
    DEBUG(type,level,format,##args)
#endif

#ifdef NO_PANIC
#undef NO_PANIC
#endif

#ifdef NO_WARNING
#undef NO_WARNING
#endif

#  define CHECK_STATEMENT(a) { int err; if ( (err = a) != 0 ) { \
			printk("%s: CHECK_STATEMENT failed line %d (err = %d)", __PRETTY_FUNCTION__, __LINE__, err);\
			if(!in_interrupt()) {while(1) schedule();}else{BUG();}; \
		}; };

#  ifdef TODO_LIST
#    define TODO(ch) printk("%s: not implemented (line %d) %s", __PRETTY_FUNCTION__, __LINE__, ch)
#  else
#    define TODO(ch) do {} while(0)
#  endif

#endif

#else				/* DEBUG_THIS_MODULE */
#  define DEBUG(level, format, args...) do {} while(0)
#  define DEBUG_PORT_FILTERED(channel, level, format, args...) do {} while(0)
#  define CHECK_STATEMENT(a) { a; }
#  define TODO(ch) do {} while(0)
#endif				/* DEBUG_THIS_MODULE */

#ifndef PANIC
static inline void print_mem_info(void)
{
#if 0
	int i;

/*   printk ("nr_free_pages : %d", nr_free_pages()) ; */

	for (i = 0; i < MAX_NR_ZONES; i++) {
		struct zone *zone;

		zone = zone_table[i];
		if (!zone)
			break;

		printk("Zone %d (%s) - free=%ld - active=%ld - inactive=%ld\n",
		       i, zone->name,
		       zone->free_pages, zone->nr_active, zone->nr_inactive);
	}
#else
		printk("print_mem_info: todo\n");
#endif
}
#endif

#ifdef NO_PANIC
#define PANIC(format, args...) do {} while(0)
#else
#ifndef __arch_um__
#define PANIC(format, args...) do {printk ("<0>" DEBUG_NORMAL "-- PANIC -- (%s) : " , __PRETTY_FUNCTION__); printk (format, ## args) ; __krg_panic__=1; print_mem_info(); if(in_interrupt()){BUG();}else{while(1){schedule();}}} while (0)
#else				/* __arch_um__ */
#define PANIC(format, args...) do {printk ("<0>" DEBUG_NORMAL "-- PANIC -- (%s) : ", __PRETTY_FUNCTION__); printk (format, ## args) ; __krg_panic__=1; BUG(); } while(0)
#endif
#endif

#ifdef NO_WARNING
#define WARNING(format, args...) do {} while(0)
#else
#define WARNING(format, args...) do {printk ("<0>" DEBUG_NORMAL "-- WARNING -- (%s) : ", __PRETTY_FUNCTION__); printk (format, ## args) ;} while (0)
#endif

#ifdef NO_EMPTY
#define EMPTY do {} while(0)
#else
#define EMPTY printk("%s: __function empty__\n",__PRETTY_FUNCTION__)
#endif

#define OOM { printk(DEBUG_NORMAL "OOM in %s: %d\nprocess stop\n", __PRETTY_FUNCTION__, __LINE__); if(in_interrupt()){BUG();}else{while(1) schedule();}; }

extern int __krg_panic__;

#endif				// __KRG_DEBUG__
