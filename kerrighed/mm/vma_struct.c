/** Distributed management of the VMA structure.
 *  @file vma_struct.c
 *
 *  Copyright (C) 2008-2009, Renaud Lottiaux, Kerlabs.
 */

#include <linux/mm.h>
#include <linux/rmap.h>

void partial_init_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
	vma->vm_mm = mm;
	vma->vm_next = NULL;
	INIT_LIST_HEAD (&vma->anon_vma_node);
	vma->vm_truncate_count = 0;
	memset (&vma->shared, 0, sizeof (vma->shared));
	memset (&vma->vm_rb, 0, sizeof (vma->vm_rb));
	vma->vm_private_data = NULL;
}



int alloc_fake_vma(struct mm_struct *mm,
		   unsigned long start,
		   unsigned long end)
{
	struct vm_area_struct *vma;
	struct anon_vma *anon_vma;
	int r = 0;

	vma = kmem_cache_alloc(vm_area_cachep, GFP_ATOMIC);
	if (!vma)
		return -ENOMEM;

	partial_init_vma (mm, vma);
	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_file = NULL;
	vma->vm_ops = NULL;
	vma->anon_vma = NULL;
	vma->vm_flags = VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE |
		VM_MAYEXEC;

	r = insert_vm_struct (mm, vma);
	if (unlikely(r))
		goto err;

	anon_vma = kmem_cache_alloc(anon_vma_cachep, GFP_ATOMIC);
	if (!anon_vma) {
		r = -ENOMEM;
		goto err;
	}

	spin_lock(&mm->page_table_lock);
	vma->anon_vma = anon_vma;
	list_add_tail(&vma->anon_vma_node, &anon_vma->head);
	spin_unlock(&mm->page_table_lock);

	return 0;
err:
	kmem_cache_free(vm_area_cachep, vma);
	return r;
}
