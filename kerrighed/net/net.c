/*
 *  kerrighed/net/net.c
 *
 *  Copyright (C) 2010, Louis Rilling - Kerlabs
 */

#include <kerrighed/krg_clusterip.h>

int init_krg_net(void)
{
	return krgip_cluster_ip_start();
}

void cleanup_krg_net(void)
{
}
