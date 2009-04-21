#ifndef __KRG_DEBUG__
#define __KRG_DEBUG__

#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/hardirq.h>

//#define NO_PANIC
//#define NO_WARNING

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
#define PANIC(format, args...) do {printk ("<0>-- PANIC -- (%s) : " , __PRETTY_FUNCTION__); printk (format, ## args) ; __krg_panic__=1; print_mem_info(); if(in_interrupt()){BUG();}else{while(1){schedule();}}} while (0)
#else				/* __arch_um__ */
#define PANIC(format, args...) do {printk ("<0>-- PANIC -- (%s) : ", __PRETTY_FUNCTION__); printk (format, ## args) ; __krg_panic__=1; BUG(); } while(0)
#endif
#endif

#ifdef NO_WARNING
#define WARNING(format, args...) do {} while(0)
#else
#define WARNING(format, args...) do {printk ("<0>-- WARNING -- (%s) : ", __PRETTY_FUNCTION__); printk (format, ## args) ;} while (0)
#endif

#ifdef NO_EMPTY
#define EMPTY do {} while(0)
#else
#define EMPTY printk("%s: __function empty__\n",__PRETTY_FUNCTION__)
#endif

#define OOM { printk("OOM in %s: %d\nprocess stop\n", __PRETTY_FUNCTION__, __LINE__); if(in_interrupt()){BUG();}else{while(1) schedule();}; }

extern int __krg_panic__;

#endif				// __KRG_DEBUG__
