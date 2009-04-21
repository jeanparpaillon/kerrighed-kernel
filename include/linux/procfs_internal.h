#ifndef __PROCFS_INTERNAL_H__
#define __PROCFS_INTERNAL_H__

/* All definitions below are moved from fs/proc/internal.h */
#ifdef CONFIG_KRG_PROCFS

struct vmalloc_info {
	unsigned long	used;
	unsigned long	largest_chunk;
};

#ifdef CONFIG_MMU
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)
extern void get_vmalloc_info(struct vmalloc_info *vmi);
#else

#define VMALLOC_TOTAL 0UL
#define get_vmalloc_info(vmi)			\
do {						\
	(vmi)->used = 0;			\
	(vmi)->largest_chunk = 0;		\
} while(0)
#endif

#endif /* CONFIG_KRG_PROCFS */

#endif /* __PROCFS_INTERNAL_H__ */
