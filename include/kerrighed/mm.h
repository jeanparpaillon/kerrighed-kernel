#ifndef __KKRG_MM__
#define __KKRG_MM__

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/sched.h>

#include <kddm/kddm_grab_object.h>
#include <kddm/kddm_put_object.h>


#ifdef CONFIG_USERMODE
#ifdef PTE_MASK
// At this time (2.6.11) PTE_MASK is not defined in UM, so as soon as this
// will be defined, we will remove this part
#warning PTE_MASK already defined
#else
#define PTE_MASK PAGE_MASK
#endif
#endif

/** Exported Functions **/

int alloc_ldt(mm_context_t *pc, int mincount, int reload) ;
void exit_mm(struct task_struct * tsk);
struct vm_area_struct *remove_vma(struct vm_area_struct *vma);
#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))
struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p);
int __dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm, int anon_only);
void detach_vmas_to_be_unmapped(struct mm_struct *mm,
				struct vm_area_struct *vma,
				struct vm_area_struct *prev,
				unsigned long end);
void unmap_region(struct mm_struct *mm, struct vm_area_struct *vma,
		  struct vm_area_struct *prev, unsigned long start,
		  unsigned long end);

void remove_vma_list(struct mm_struct *mm, struct vm_area_struct *vma);

/** Exported Variables **/

extern struct kmem_cache *mm_cachep;
extern struct vm_operations_struct generic_file_vm_ops ;
extern struct kddm_set *mm_struct_kddm_set;

int special_mapping_vm_ops_krgsyms_register(void);
int special_mapping_vm_ops_krgsyms_unregister(void);

static inline void dump_vma(struct task_struct *tsk)
{
	struct vm_area_struct *vma;

	vma = tsk->mm->mmap;

	while(vma) {
		printk ("[0x%08lx:0x%08lx] - flags 0x%08lx - offset 0x%08lx - "
			"file %p\n", vma->vm_start, vma->vm_end, vma->vm_flags,
			vma->vm_pgoff, vma->vm_file);

		vma = vma->vm_next;
	}
}

static inline int anon_vma(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_SHARED)
		return 0;

	if (!vma->vm_file)
		return 1;

	return (vma->anon_vma || vma->vm_flags & VM_KDDM);
}

#ifdef CONFIG_KRG_FAF
void use_mm(struct mm_struct *mm);
void unuse_mm(struct mm_struct *mm);
#endif

void mm_struct_pin(struct mm_struct *mm);
void mm_struct_unpin(struct mm_struct *mm);

/** Kerrighed Kernel Hooks **/

extern void (*kh_mm_get) (struct mm_struct *mm);
extern void (*kh_mm_release) (struct mm_struct *mm, int notify);

int krg_do_execve(struct task_struct *tsk, struct mm_struct *mm);
extern struct mm_struct *(*kh_copy_mm)(struct task_struct *tsk,
				       struct mm_struct *oldmm,
				       unsigned long clone_flags);

extern void (*kh_fill_pte)(struct mm_struct *mm, unsigned long addr,
			   pte_t *pte);
extern void (*kh_zap_pte)(struct mm_struct *mm, unsigned long addr,
			  pte_t *pte);

int try_to_flush_page(struct page *page);

void krg_notify_mem(int mem_usage);

void krg_check_vma_link(struct vm_area_struct *vma);

static inline void krg_lock_mm(struct mm_struct *mm)
{
	_kddm_grab_object_no_ft (mm_struct_kddm_set, mm->mm_id);
}

static inline void krg_unlock_mm(struct mm_struct *mm)
{
	_kddm_put_object (mm_struct_kddm_set, mm->mm_id);
}

void krg_do_mmap_region(struct vm_area_struct *vma, unsigned long flags,
			unsigned int vm_flags);

void krg_do_munmap(struct mm_struct *mm, unsigned long start, size_t len);

void krg_do_mremap(struct mm_struct *mm, unsigned long addr,
		   unsigned long old_len, unsigned long new_len,
		   unsigned long flags, unsigned long new_addr,
		   unsigned long _new_addr, unsigned long lock_limit);

void krg_do_brk(struct mm_struct *mm, unsigned long brk,
		unsigned long lock_limit, unsigned long data_limit);

int krg_expand_stack(struct vm_area_struct *vma, unsigned long address);

void krg_do_mprotect(struct mm_struct *mm, unsigned long start, size_t len,
		     unsigned long prot, int personality);

#define TestClearPageLRU(page)  test_and_clear_bit(PG_lru, &(page)->flags)

#endif // __KKRG_MM__

