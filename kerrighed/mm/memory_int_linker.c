/** Container memory interface linker.
 *  @file memory_int_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/string.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/acct.h>
#include <kerrighed/pid.h>
#include <asm/tlb.h>

#include <kddm/kddm.h>
#include "memory_int_linker.h"
#include "memory_io_linker.h"
#include "mm_struct.h"
#include "page_table_tree.h"


struct vm_operations_struct null_vm_ops = {};



/** Create the anonymous kddm_set for the given process.
 *  @author Renaud Lottiaux
 *
 *  @param ghost    Ghost where data should be stored.
 *  @param tsk      The task to create an anon kddm_set for.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 *
 *  The kddm_set is created empty. The caller must fill it with existing
 *  pages.
 */
int create_anon_vma_kddm_set (struct mm_struct *mm)
{
	struct kddm_set *set;

	set = __create_new_kddm_set(kddm_def_ns, 0, &kddm_pt_set_ops, mm,
				    MEMORY_LINKER, kerrighed_node_id,
				    PAGE_SIZE, NULL, 0, 0);

	if (IS_ERR(set))
		return PTR_ERR(set);

	set_anon_vma_kddm_set(mm, set);

	return 0;
}



/*****************************************************************************/
/*                                                                           */
/*                       MEMORY INTERFACE LINKER CREATION                    */
/*                                                                           */
/*****************************************************************************/



/** Link a VMA to the anon memory kddm set
 *  @author Renaud Lottiaux
 *
 *  @param  vma          vm_area to link with a kddm set.
 *
 *  @return   0 If everything OK,
 *            Negative value otherwise.
 */
int check_link_vma_to_anon_memory_kddm_set (struct vm_area_struct *vma)
{
	int r = 0;

	if (!anon_vma(vma))
		return r;

	/* Do not share the VDSO page as anonymous memory. Anyway it is always
	 * available on all nodes. */
	if (arch_vma_name(vma))
		return r;

	if (vma->vm_ops == &anon_memory_kddm_vmops)
		return r;

	/*** Make the VMA a kddm set VMA ***/

	BUG_ON(vma->vm_flags & VM_SHARED);

	BUG_ON(vma->initial_vm_ops == &anon_memory_kddm_vmops);
	if (vma->vm_ops == NULL)
		vma->initial_vm_ops = &null_vm_ops;
	else
		vma->initial_vm_ops = vma->vm_ops;
	vma->vm_ops = &anon_memory_kddm_vmops;
	vma->vm_flags |= VM_KDDM;

	return r;
}



static inline void memory_kddm_readahead (struct kddm_set * set,
                                          objid_t start,
					  int upper_limit)
{
	int i, ra_restart_limit;
	int ra_start, ra_end;

	return ;

	/* Disable prefetching for threads */
	if (!thread_group_empty(current))
		return;

	ra_restart_limit = set->last_ra_start + (set->ra_window_size / 2);

	if (start <= set->last_ra_start - set->ra_window_size / 2)
	{
		ra_start = start;
		ra_end = min_t (int, set->last_ra_start - 1,
				ra_start + set->ra_window_size);

		goto do_prefetch;
	}

	if (start >= ra_restart_limit)
	{
		ra_end = start + set->ra_window_size;
		ra_start = max_t (int, start, set->last_ra_start +
				  set->ra_window_size);

		goto do_prefetch;
	}

	return;

do_prefetch:
	set->last_ra_start = start;
	ra_end = min_t (int, ra_end, upper_limit);

	for (i = ra_start; i < ra_end; i++)
		_async_kddm_grab_object_no_ft (set, i);
}



/*****************************************************************************/
/*                                                                           */
/*                    MEMORY INTERFACE LINKER OPERATIONS                     */
/*                                                                           */
/*****************************************************************************/

static inline pte_t maybe_mkwrite(pte_t pte, struct vm_area_struct *vma)
{
	if (likely(vma->vm_flags & VM_WRITE))
		pte = pte_mkwrite(pte);
	return pte;
}

void map_kddm_page(struct vm_area_struct *vma,
		   unsigned long address,
		   struct page *page,
		   int write)
{
	struct mm_struct *mm = vma->vm_mm;
	spinlock_t *ptl;
	pte_t *ptep, pte;

	ptep = get_locked_pte(mm, address, &ptl);
	BUG_ON(!ptep);

	pte = mk_pte(page, vma->vm_page_prot);
	if (write)
		pte = maybe_mkwrite(pte_mkdirty(pte), vma);
	else
		pte = pte_wrprotect(pte);
	set_pte_at(mm, address, ptep, pte);
	update_mmu_cache(vma, address, pte);
	pte_unmap_unlock(ptep, ptl);
}

/** Handle a nopage fault on an anonymous VMA.
 * @author Renaud Lottiaux
 *
 *  @param  vma           vm_area of the faulting address area
 *  @param  address       address of the page fault
 *  @param  write_access  0 = read fault, 1 = write fault
 *  @return               Physical address of the page
 */

int anon_memory_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page, *new_page;
	struct kddm_set *set;
	objid_t objid;
	unsigned long address;
	int ret = VM_FAULT_MINOR;
	int write_access = vmf->flags & FAULT_FLAG_WRITE;

	address = (unsigned long)(vmf->virtual_address) & PAGE_MASK;

	BUG_ON(!vma);

	set = vma->vm_mm->anon_vma_kddm_set;

	BUG_ON(!set);

	objid = address / PAGE_SIZE;

	if (thread_group_empty(current)) {
		write_access = 1;
		if (set->def_owner != kerrighed_node_id)
			memory_kddm_readahead (set, objid,
					       vma->vm_start / PAGE_SIZE);
	}

	if (vma->vm_file)
	{
		/* Mapped file VMA no page access */

		/* First, try to check if the page already exist in the anon
		 * kddm set */
		if (write_access)
			page = _kddm_grab_object_manual_ft(set, objid);
		else
			page = _kddm_get_object_manual_ft (set, objid);

		if (page != NULL)
			goto done;

		/* Ok, the page is not present in the anon kddm set, let's
		 * load it */

		ret = vma->initial_vm_ops->fault(vma, vmf);
		if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE)))
			goto exit_error;

		/* Copy the cache page into an anonymous page (copy on write
		 * will be done later on)
		 */
		new_page = alloc_page_vma(GFP_HIGHUSER, vma, address);
		if (!new_page)
		{
			ret = VM_FAULT_OOM;
			goto exit_error;
		}
		copy_user_highpage(new_page, vmf->page, address, vma);

		if (ret & VM_FAULT_LOCKED) {
			unlock_page(vmf->page);
			ret &= ~VM_FAULT_LOCKED;
		}

		page_cache_release(vmf->page);
		page = new_page;

		_kddm_set_object(set, objid, page);
	}
	else
	{
		/* Memory VMA no page access */

		if (write_access)
			/* TODO: ensure that all work done by
			 * alloc_zeroed_user_highpage() is done on
			 * archs other than x86.
			 */
			page = _kddm_grab_object (set, objid);
		else
			page = _kddm_get_object (set, objid);
	}

done:
	if (page->mapping) {
		if (page_mapcount(page) == 0) {
			printk ("Null mapping count, non null mapping address "
				": 0x%p\n", page->mapping);
			page->mapping = NULL;
		}
		else {
/********************* DEBUG ONLY *********************************/
			struct anon_vma *anon_vma;

			BUG_ON (!PageAnon(page));

			anon_vma = (void *)page->mapping - PAGE_MAPPING_ANON;
			if (anon_vma != vma->anon_vma) {
				printk ("Page mapping : %p - VMA anon : %p\n",
					anon_vma, vma->anon_vma);

				printk ("Fault af 0x%08lx for "
	       "process %s (%d - %p). Access : %d in vma [0x%08lx:0x%08lx] "
	       "(0x%08lx) - file: 0x%p, anon_vma : 0x%p\n", address,
	       current->comm, current->pid, current, write_access,
	       vma->vm_start, vma->vm_end, (unsigned long) vma, vma->vm_file,
	       vma->anon_vma);

				while(1) schedule();
			}

/********************* END DEBUG ONLY ******************************/
		}
	}

	map_kddm_page(vma, objid * PAGE_SIZE, page, write_access);

	vmf->page = page;

exit_error:
	_kddm_put_object (set, objid);

	return ret;
}



/** Handle a wppage fault on a memory kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param  vma       vm_area of the faulting address area
 *  @param  virtaddr  Virtual address of the page fault
 *  @return           Physical address of the page
 */
struct page *anon_memory_wppage (struct vm_area_struct *vma,
				 unsigned long address,
				 struct page *old_page)
{
	struct page *page;
	struct kddm_set *set;
	objid_t objid;

	BUG_ON (vma == NULL);

	set = vma->vm_mm->anon_vma_kddm_set;

	BUG_ON (set == NULL);

	objid = address / PAGE_SIZE;

	/* If the old page is hosted by a KDDM, the KDDM layer will do the
	 * copy on write. If the page is not hosted by a KDDM, we must copy the
	 * page here, after the grab.
	 */
	if (old_page && old_page->obj_entry)
		old_page = NULL;

	if (set->def_owner != kerrighed_node_id)
		memory_kddm_readahead (set, objid, vma->vm_start / PAGE_SIZE);

	page = _kddm_grab_object_cow (set, objid);

	if (old_page && old_page != page)
		copy_user_highpage(page, old_page, address, vma);

	map_kddm_page(vma, objid * PAGE_SIZE, page, 1);

	_kddm_put_object (set, objid);

	return page;
}


void anon_memory_close (struct vm_area_struct *vma)
{
}


/*
 * Virtual Memory Operation.
 *  Redefinition of some virtual memory operations. Used to handle page faults
 *  on a memory kddm set.
 *  @arg @c nopage is called when a page is touched for the first time
 * 	 (i.e. the page is not in memory and is not swap).
 *  @arg @c wppage is called when a page with read access is touch with a write
 *          access.
 *  @arg @c map is called when a vma is created or extended by do_mmap().
 */
struct vm_operations_struct anon_memory_kddm_vmops = {
	close:  anon_memory_close,
	fault: anon_memory_fault,
	wppage: anon_memory_wppage,
};
