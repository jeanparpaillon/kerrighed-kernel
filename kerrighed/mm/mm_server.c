/** Kerrighed MM servers.
 *  @file mm_server.c
 *
 *  Copyright (C) 2008, Renaud Lottiaux, Kerlabs.
 */
#include <linux/kernel.h>
#include <linux/mm.h>

#include <net/krgrpc/rpc.h>
#include "mm_struct.h"
#include "mm_server.h"

/** Handler for remote munmap.
 *  @author Renaud Lottiaux
 */
int handle_do_munmap (struct rpc_desc* desc,
		      void *msgIn, size_t size)
{
	struct vm_area_struct *vma;
	struct mm_munmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	vma = find_vma(mm, msg->start);
	if (vma)
		zap_page_range(vma, msg->start, msg->len, NULL);

	krg_put_mm(msg->mm_id);

	return 0;
}



/* MM handler Initialisation */

void mm_server_init (void)
{
	rpc_register_int(RPC_MM_MUNMAP, handle_do_munmap, 0);
}



/* MM server Finalization */

void mm_server_finalize (void)
{
}
