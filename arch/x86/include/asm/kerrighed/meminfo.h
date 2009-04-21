#ifndef __X86_MEMINFO_H__
#define __X86_MEMINFO_H__

typedef struct {
	unsigned long direct_map_4k;
	unsigned long direct_map_2M;
	unsigned long direct_map_1G;
	int direct_gbpages;
} krg_arch_meminfo_t;

#endif /* __X86_MEMINFO_H__ */
