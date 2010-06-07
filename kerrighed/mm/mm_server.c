/** Kerrighed MM servers.
 *  @file mm_server.c
 *
 *  Copyright (C) 2008-2010, Renaud Lottiaux, Kerlabs.
 */
#include <linux/kernel.h>
#include <linux/mm.h>

#include <net/krgrpc/rpc.h>
#include "mm_struct.h"
#include "mm_server.h"
#include "memory_int_linker.h"

/** Handler for remote mmap.
 *  @author Renaud Lottiaux
 */
int handle_do_mmap_region (struct rpc_desc* desc,
			   void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	__mmap_region(mm, NULL, msg->start, msg->len, msg->flags,
		      msg->vm_flags, msg->pgoff, 1);

	vma = find_vma(mm, msg->start);
	BUG_ON(!vma || vma->vm_start != msg->start);

	check_link_vma_to_anon_memory_kddm_set (vma);

	up_write(&mm->mmap_sem);

	krg_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote mremap.
 *  @author Renaud Lottiaux
 */
int handle_do_mremap (struct rpc_desc* desc,
		      void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	__do_mremap(mm, msg->addr, msg->old_len, msg->new_len, msg->flags,
		    msg->new_addr, &msg->_new_addr, msg->lock_limit);

	up_write(&mm->mmap_sem);

	krg_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote munmap.
 *  @author Renaud Lottiaux
 */
int handle_do_munmap (struct rpc_desc* desc,
		      void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	do_munmap(mm, msg->start, msg->len);

	up_write(&mm->mmap_sem);

	krg_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote brk.
 *  @author Renaud Lottiaux
 */
int handle_do_brk (struct rpc_desc* desc,
		   void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	__sys_brk(mm, msg->brk, msg->lock_limit, msg->data_limit);

	up_write(&mm->mmap_sem);

	krg_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote expand_stack.
 *  @author Renaud Lottiaux
 */
int handle_expand_stack (struct rpc_desc* desc,
			 void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	int r;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return -EINVAL;

	down_write(&mm->mmap_sem);

	vma = find_vma(mm, msg->start);

	r = __expand_stack(vma, msg->flags);

	up_write(&mm->mmap_sem);

	krg_put_mm(msg->mm_id);

	return r;
}

/** Handler for remote mprotect.
 *  @author Renaud Lottiaux
 */
int handle_do_mprotect (struct rpc_desc* desc,
			void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = krg_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	do_mprotect (mm, msg->start, msg->len, msg->prot, msg->personality);

	krg_put_mm(msg->mm_id);

	return 0;
}

/* MM handler Initialisation */

void mm_server_init (void)
{
	rpc_register_int(RPC_MM_MMAP_REGION, handle_do_mmap_region, 0);
	rpc_register_int(RPC_MM_MREMAP, handle_do_mremap, 0);
	rpc_register_int(RPC_MM_MUNMAP, handle_do_munmap, 0);
	rpc_register_int(RPC_MM_DO_BRK, handle_do_brk, 0);
	rpc_register_int(RPC_MM_EXPAND_STACK, handle_expand_stack, 0);
	rpc_register_int(RPC_MM_MPROTECT, handle_do_mprotect, 0);
}



/* MM server Finalization */

void mm_server_finalize (void)
{
}
