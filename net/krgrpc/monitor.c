/**
 *
 *  Copyright (C) 2007 Pascal Gallard, Kerlabs <Pascal.Gallard@kerlabs.com>
 *
 */

#include <linux/timer.h>
#include <linux/workqueue.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/krginit.h>

#include <kerrighed/workqueue.h>
#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>

#include "rpc_internal.h"

static struct timer_list rpc_timer;
struct work_struct rpc_work;
struct rpc_service pingpong_service;

static void rpc_pingpong_handler (struct rpc_desc *rpc_desc,
				  void *data,
				  size_t size){
	unsigned long l = *(unsigned long*)data;

	l++;
	
	rpc_pack(rpc_desc, 0, &l, sizeof(l));
};

static void rpc_worker(struct work_struct *data)
{
	static unsigned long l = 0;
	krgnodemask_t n;
	int r;

	r = 0;
	l++;
	
	krgnodes_clear(n);
	krgnode_set(0, n);

	r = rpc_async(RPC_PINGPONG, 0, &l, sizeof(l));
	if(r<0)
		return;
	
}

static void rpc_timer_cb(unsigned long _arg)
{
	return;
	queue_work(krg_wq, &rpc_work);
	mod_timer(&rpc_timer, jiffies + 2*HZ);
}

int rpc_monitor_init(void){
	rpc_register_void(RPC_PINGPONG,
			  rpc_pingpong_handler, 0);
	
	init_timer(&rpc_timer);
	rpc_timer.function = rpc_timer_cb;
	rpc_timer.data = 0;
	if(kerrighed_node_id != 0)
		mod_timer(&rpc_timer, jiffies + 10*HZ);
	INIT_WORK(&rpc_work, rpc_worker);

	return 0;
}

void rpc_monitor_cleanup(void){
}
