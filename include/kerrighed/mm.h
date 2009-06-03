#ifndef __KKRG_MM__
#define __KKRG_MM__

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched.h>

static inline int anon_vma(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_SHARED)
		return 0;

	if (!vma->vm_file)
		return 1;

	return (vma->anon_vma || vma->vm_flags & VM_KDDM);
}

#endif
