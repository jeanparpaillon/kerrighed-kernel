/*
 *  arch/x86/kerrighed/krg_x86.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 */

#define MODULE_NAME "arch"

#include "debug_x86.h"

int init_arch(void)
{
	init_arch_debug();

	return 0;
}

void cleanup_arch(void)
{
}
