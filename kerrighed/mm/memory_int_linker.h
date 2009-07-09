/** KDDM Memory interface Linker.
 *  @file memory_int_linker.h
 *
 *  Link kddm sets and linux memory system.
 *  @author Renaud Lottiaux
 */

#ifndef __MEMORY_INT_LINKER__
#define __MEMORY_INT_LINKER__

#include <linux/mm.h>

#include <kddm/kddm.h>

#include <kerrighed/debug.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct vm_operations_struct anon_memory_kddm_vmops;
extern struct vm_operations_struct null_vm_ops;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Link a VMA to an anon kddm set.
 *  @author Renaud Lottiaux
 *
 *  @param vma     vma structure to link to the anon KDDM set.
 *
 *  The kddm set must have been allocated and initialized. The
 *  VM_CONTAINER flag is added to the vm_cflags field of the vma. The
 *  kddm set id is stored in the vm_ctnr field and vm operations are
 *  set to the operations used by kddm sets, depending on the
 *  kddm set type.
 */
int check_link_vma_to_anon_memory_kddm_set (struct vm_area_struct *vma);

int create_anon_vma_kddm_set (struct mm_struct *dst_mm);

static inline void restore_initial_vm_ops (struct vm_area_struct *vma)
{
	if (vma->initial_vm_ops == NULL)
		return;

	if (vma->initial_vm_ops == &null_vm_ops)
		vma->vm_ops = NULL;
	else
		vma->vm_ops = vma->initial_vm_ops;
}



/* Return the page table entry associated to a virtual address */
static inline pte_t *get_pte_no_lock (struct mm_struct *mm, unsigned long addr)
{
	pgd_t * pgd = pgd_offset(mm, addr);
	pud_t * pud = pud_alloc(mm, pgd, addr);
	pmd_t * pmd;

	if (!pud)
		return NULL;

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	if (unlikely(!pmd_present(*(pmd))) &&
	    __pte_alloc(mm, pmd, addr))
		return NULL;

	return pte_offset_map(pmd, addr);
}

#endif /* __MEMORY_INT_LINKER__ */
