/*
 *  Kerrighed/modules/arch/x86_64/krg_x86_64.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 */

#define MODULE_NAME "arch"

#include "debug_x86_64.h"

int init_arch(void)
{
#ifdef CONFIG_KRG_DEBUG
	init_arch_x86_64_debug();
#endif

	return 0;
}

void cleanup_arch(void)
{
}
