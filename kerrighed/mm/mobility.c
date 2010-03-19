/** Implementation of process Virtual Memory mobility mechanisms.
 *  @file vm_mobility.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2009, Renaud Lottiaux, Kerlabs.
 *
 *  Implementation of functions used to migrate, duplicate and checkpoint
 *  process virtual memory.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/vmalloc.h>
#include <linux/init_task.h>
#include <asm/elf.h>
#include <linux/file.h>
#ifndef CONFIG_USERMODE
#include <asm/ldt.h>
#else
#include <asm/arch/ldt.h>
#endif
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <kerrighed/krgsyms.h>
#include <kerrighed/krginit.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kerrighed/ghost.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/action.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/pid.h>
#include <kerrighed/sys/checkpoint.h>
#include "vma_struct.h"

#include "memory_int_linker.h"
#include "memory_io_linker.h"
#include "mm_struct.h"

#define FILE_TABLE_SIZE 16

void unimport_mm_struct(struct task_struct *task);

void __vma_link_file(struct vm_area_struct *vma);

extern struct vm_operations_struct special_mapping_vmops;

/*****************************************************************************/
/*                                                                           */
/*                               TOOLS FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



void free_ghost_mm (struct task_struct *tsk)
{
	/* if not NULL, mm_release will try to write in userspace... which
	 * does not exist anyway since we are in kernel thread context
	 */
	tsk->clear_child_tid = NULL;
	/* Do not notify end of vfork here */
	tsk->vfork_done = NULL;
	mmput (tsk->mm);

	/* exit_mm supposes current == tsk, and therefore, leaves one
	 * reference to tsk->mm because of mm->active_mm which will be dropped
	 * during schedule.
	 * The ghost mm will never be scheduled out because no real process is
	 * associated to it, thereofore, we take care of the active_mm case
	 * here
	 */
	if (!tsk->mm) {
		mmdrop (tsk->active_mm);
		tsk->active_mm = NULL;
	}
}



/*****************************************************************************/
/*                                                                           */
/*                              EXPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

struct cr_mm_region_excluded {
	struct cr_mm_region region;
	struct mm_struct *mm;
};

static int is_page_contained_in_mm_region(struct cr_mm_region *region,
					  unsigned long addr)
{
	if (region->addr <= addr
	    && addr + PAGE_SIZE <= region->addr + region->size)
		return 1;

	return 0;
}

static int is_page_excluded_from_checkpoint(struct app_struct *app,
					    struct mm_struct *mm,
					    unsigned long addr)
{
	struct cr_mm_region *mm_region;
	struct cr_mm_region_excluded *mm_excl_region;

	mm_region = app->checkpoint.first_mm_region;

	while (mm_region) {

		mm_excl_region = container_of(mm_region,
					      struct cr_mm_region_excluded,
					      region);

		if (mm == mm_excl_region->mm
		    && is_page_contained_in_mm_region(
			    &mm_excl_region->region, addr))
			return 1;

		mm_region = mm_region->next;
	}

	return 0;
}

static int __cr_exclude_mm_region(struct app_struct *app, struct mm_struct *mm,
				  unsigned long addr, size_t size)
{
	struct cr_mm_region_excluded *mm_region;

	mm_region = kmalloc(sizeof(struct cr_mm_region_excluded), GFP_KERNEL);
	if (!mm_region)
		return -ENOMEM;

	mm_region->mm = mm;
	mm_region->region.addr = addr;
	mm_region->region.size = size;

	/* we don't care about order */
	if (app->checkpoint.first_mm_region)
		mm_region->region.next = app->checkpoint.first_mm_region;
	else
		mm_region->region.next = NULL;

	app->checkpoint.first_mm_region = &mm_region->region;

	return 0;
}

int cr_exclude_mm_region(struct app_struct *app, pid_t pid,
			 unsigned long addr, size_t size)
{
	task_state_t *t;

	list_for_each_entry(t, &app->tasks, next_task) {
		if (task_pid_knr(t->task) == pid)
			return __cr_exclude_mm_region(app, t->task->mm,
						      addr, size);
	}

	return 0; /* process is not on this node, simply ignore */
}

void cr_free_mm_exclusions(struct app_struct *app)
{
	struct cr_mm_region_excluded *mm_region;
	struct cr_mm_region *element;

	element = app->checkpoint.first_mm_region;

	while (element) {
		mm_region = container_of(element,
					 struct cr_mm_region_excluded,
					 region);

		element = mm_region->region.next;

		kfree(mm_region);
	}

	app->checkpoint.first_mm_region = NULL;
}

/** Export one physical page of a process.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param app      Application hosting task(s) related to the vma.
 *  @param ghost    Ghost where data should be stored.
 *  @param vma      The memory area hosting the page.
 *  @param addr     Virtual address of the page.
 *
 *  @return  1 if a page has been exported.
 *           0 if no page has been exported.
 *           Negative value otherwise.
 */
static int export_one_page(struct app_struct *app, ghost_t *ghost,
			   struct vm_area_struct *vma, unsigned long addr)
{
	struct kddm_set *set = NULL;
	unsigned long pfn;
	spinlock_t *ptl;
	struct page *page = NULL;
	char *page_addr;
	objid_t objid = 0;
	pgprot_t prot;
	pte_t *pte;
	int put_page = 0;
	int nr_exported = 0;
	int page_excluded = 0;
	int r;

	pte = get_locked_pte(vma->vm_mm, addr, &ptl);
	if (pte && pte_present(*pte)) {
		pfn = pte_pfn(*pte);
		page = pfn_to_page(pfn);
		prot = pte_pgprot(*pte);
		pte_unmap_unlock(pte, ptl);
		if (!page || !PageAnon(page))
			goto exit;
	} else {
		if (pte)
			pte_unmap_unlock(pte, ptl);

		set = vma->vm_mm->anon_vma_kddm_set;
		if (set) {
			objid = addr / PAGE_SIZE;
			page = kddm_get_object_no_ft(kddm_def_ns, set->id,
						     objid);
			prot = vma->vm_page_prot;
			put_page = 1;
		}
		if (!page)
			goto exit;
	}

	page_addr = (char *)kmap(page);

	/* Export the virtual address of the page */
	r = ghost_write(ghost, &addr, sizeof (unsigned long));
	if (r)
		goto unmap;

	/* Export the page protection */
	r = ghost_write(ghost, &prot, sizeof(pgprot_t));
	if (r)
		goto unmap;

	/* Export the physical page content unless it has been
	 * excluded from the chekpoint by the programmer */
	page_excluded = is_page_excluded_from_checkpoint(app, vma->vm_mm, addr);
	r = ghost_write_type(ghost, page_excluded);
	if (r)
		goto unmap;

	if (!page_excluded) {
		r = ghost_write(ghost, (void*)page_addr, PAGE_SIZE);
		if (r)
			goto unmap;
	}

unmap:
	kunmap(page);
	nr_exported = r ? r : 1;

exit:
	if (put_page)
		kddm_put_object(kddm_def_ns, set->id, objid);

	return nr_exported;
}

/** Export the physical pages hosted by a VMA.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param app      Application hosting task(s) related to the vma.
 *  @param ghost    Ghost where data should be stored.
 *  @param tsk      Task to export memory pages from.
 *  @param vma      The VMA to export pages from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static int export_vma_pages(struct app_struct *app, ghost_t *ghost,
			    struct vm_area_struct *vma)
{
	unsigned long addr;
	int nr_pages_sent = 0;
	int r;

	if (!anon_vma(vma))
		goto done;

	for (addr = vma->vm_start; addr < vma->vm_end; addr += PAGE_SIZE) {
		r = export_one_page(app, ghost, vma, addr);
		if (r < 0)
			goto out;
		nr_pages_sent += r;
	}

done:
	/* Mark the end of the page exported */
	addr = 0;
	r = ghost_write (ghost, &addr, sizeof (unsigned long));
	if (r)
		goto out;

	r = ghost_write (ghost, &nr_pages_sent, sizeof (int)) ;

out:
	return r;
}

/** This function exports the physical memory pages of a process
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param app         Application hosting task(s) related to the mm_struct.
 *  @param ghost       Ghost where pages should be stored.
 *  @param mm          mm_struct to export memory pages to.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_process_pages(struct app_struct *app,
			 ghost_t * ghost,
                         struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int r = 0;

	BUG_ON(!app);
	BUG_ON(!mm);

	/* Export process VMAs */
	vma = mm->mmap;
	BUG_ON(!vma);

	while (vma) {
		if (vma->vm_ops != &special_mapping_vmops) {
			r = export_vma_pages(app, ghost, vma);
			if (r)
				goto out;
		}
		vma = vma->vm_next;
	}

	{
		int magic = 962134;
		r = ghost_write(ghost, &magic, sizeof(int));
	}

out:
	return r;
}

/** Export one VMA into the ghost.
 *  @author Renaud Lottiaux
 *
 *  @param ghost    Ghost where data should be stored.
 *  @param tsk      The task to export the VMA from.
 *  @param vma      The VMA to export.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static int export_one_vma (struct epm_action *action,
			   ghost_t *ghost,
                           struct task_struct *tsk,
                           struct vm_area_struct *vma,
			   hashtable_t *file_table)
{
	krgsyms_val_t vm_ops_type, initial_vm_ops_type;
	int r;

	/* First, check if we need to link the VMA to the anon kddm_set */

	if (tsk->mm->anon_vma_kddm_set)
		check_link_vma_to_anon_memory_kddm_set (vma);

	/* Export the vm_area_struct */
	r = ghost_write (ghost, vma, sizeof (struct vm_area_struct));
	if (r)
		goto out;

#ifdef CONFIG_KRG_DVFS
	/* Export the associated file */
	r = export_vma_file (action, ghost, tsk, vma, file_table);
	if (r)
		goto out;
#endif
	/* Define and export the vm_ops type of the vma */

	r = -EPERM;
	vm_ops_type = krgsyms_export (vma->vm_ops);
	if (vma->vm_ops && vm_ops_type == KRGSYMS_UNDEF)
		goto out;
	initial_vm_ops_type = krgsyms_export (vma->initial_vm_ops);
	if (vma->initial_vm_ops && initial_vm_ops_type == KRGSYMS_UNDEF)
		goto out;

	BUG_ON(vma->vm_private_data && vm_ops_type != KRGSYMS_VM_OPS_SPECIAL_MAPPING);

	r = ghost_write (ghost, &vm_ops_type, sizeof (krgsyms_val_t));
	if (r)
		goto out;

	r = ghost_write (ghost, &initial_vm_ops_type, sizeof (krgsyms_val_t));

out:
	return r;
}



/** This function export the list of VMA to the ghost
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be stored.
 *  @param tsk    Task to export vma data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_vmas (struct epm_action *action,
		 ghost_t *ghost,
                 struct task_struct *tsk)
{
	struct vm_area_struct *vma;
	hashtable_t *file_table;

	int r;

	BUG_ON (tsk == NULL);
	BUG_ON (tsk->mm == NULL);

	file_table = hashtable_new (FILE_TABLE_SIZE);
	if (!file_table)
		return -ENOMEM;

	/* Export process VMAs */

	r = ghost_write(ghost, &tsk->mm->map_count, sizeof(int));
	if (r)
		goto out;

	vma = tsk->mm->mmap;

	while (vma != NULL) {
		r = export_one_vma (action, ghost, tsk, vma, file_table);
		if (r)
			goto out;
		vma = vma->vm_next;
	}

	{
		int magic = 650874;

		r = ghost_write(ghost, &magic, sizeof(int));
	}

out:
	hashtable_free(file_table);

	return r;
}



/** This function exports the context structure of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where data should be stored.
 *  @param mm     MM hosting context to export.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_context_struct (ghost_t * ghost,
                           struct mm_struct *mm)
{
	int r = 0;

#ifndef CONFIG_USERMODE
	if (mm->context.ldt) {
		r = ghost_write(ghost,
				mm->context.ldt,
				mm->context.size * LDT_ENTRY_SIZE);
		if (r)
			goto err;
	}
#endif
err:
	return r;
}

static int export_mm_counters(struct epm_action *action,
			      ghost_t *ghost,
			      struct mm_struct* mm,
			      struct mm_struct *exported_mm)
{
	int r;

	r = ghost_write(ghost, mm, sizeof(struct mm_struct));
	r = ghost_write(ghost, &exported_mm->mm_tasks, sizeof(atomic_t));
	return r;
}

static int cr_add_vmas_files_to_shared_table(struct task_struct *task)
{
	int r = 0;
	struct vm_area_struct *vma;
	vma = task->mm->mmap;

	while (vma != NULL) {

		if (vma->vm_file) {
			r = cr_add_file_to_shared_table(task, -1,
							vma->vm_file, 0);
			if (r == -ENOKEY) /* the file was already in the list */
				r = 0;

			if (r)
				goto error;
		}
		vma = vma->vm_next;
	}

error:
	return r;
}

static int cr_add_exe_file_to_shared_table(struct task_struct *task)
{
	int r = 0;

#ifdef CONFIG_PROC_FS
	r = cr_add_file_to_shared_table(task, -1, task->mm->exe_file, 0);
	if (r == -ENOKEY) /* the file was already in the list */
		r = 0;
#endif

	return r;
}

static int cr_export_later_mm_struct(struct epm_action *action,
				     ghost_t *ghost,
				     struct task_struct *task)
{
	int r;
	long key;

	BUG_ON(action->type != EPM_CHECKPOINT);
	BUG_ON(action->checkpoint.shared != CR_SAVE_LATER);

	key = (long)(task->mm);

	r = ghost_write(ghost, &key, sizeof(long));
	if (r)
		goto exit;

	r = add_to_shared_objects_list(task->application,
				       MM_STRUCT, key, LOCAL_ONLY, task,
				       NULL, 0);

	if (r == -ENOKEY) { /* the mm_struct was already in the list */
		r = 0;
		goto exit;
	}

	r = cr_add_exe_file_to_shared_table(task);
	if (r)
		goto exit;

	r = cr_add_vmas_files_to_shared_table(task);

exit:
	return r;
}



static inline int do_export_mm_struct(struct epm_action *action,
				      ghost_t *ghost,
				      struct mm_struct *mm)
{
	int r;

	switch (action->type) {
	  case EPM_CHECKPOINT:
		  krg_get_mm(mm->mm_id);
		  r = ghost_write(ghost, mm, sizeof(struct mm_struct));
		  krg_put_mm(mm->mm_id);
		  break;

	  default:
		  r = ghost_write(ghost, &mm->mm_id, sizeof(unique_id_t));
	}

	return r;
}



/** This function exports the virtual memory of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where VM data should be stored.
 *  @param tsk    Task to export memory data from.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int export_mm_struct(struct epm_action *action,
		     ghost_t *ghost,
		     struct task_struct *tsk)
{
	struct mm_struct *mm, *exported_mm;
	int r = 0;

	mm = tsk->mm;
	exported_mm = mm;

	switch (action->type) {
	  case EPM_CHECKPOINT:
		  if (action->checkpoint.shared == CR_SAVE_LATER) {
			  r = cr_export_later_mm_struct(action, ghost, tsk);
			  return r;
		  }
		  break;

	  case EPM_REMOTE_CLONE:
		  if (!(action->remote_clone.clone_flags & CLONE_VM)) {

			  exported_mm = krg_dup_mm(tsk, mm);
			  if (IS_ERR(exported_mm))
				  return PTR_ERR(exported_mm);

			  break;
		  }
		  /* else fall through */

	  case EPM_MIGRATE:
		  if (mm->anon_vma_kddm_set == NULL) {
			  r = init_anon_vma_kddm_set(tsk, mm);
			  if (r)
				  goto exit_put_mm;
		  }

		  break;

	  default:
		  BUG();
        }

	/* Check some currently unsupported cases */
	BUG_ON(mm->core_state);
	BUG_ON(!hlist_empty(&mm->ioctx_list));

	r = do_export_mm_struct (action, ghost, exported_mm);
	if (r)
		goto up_mmap_sem;

	down_read(&mm->mmap_sem);
	r = export_context_struct(ghost, exported_mm);
	if (r)
		goto up_mmap_sem;

#ifdef CONFIG_KRG_DVFS
	r = export_mm_exe_file(action, ghost, tsk);
	if (r)
		goto up_mmap_sem;
#endif

	r = export_vmas(action, ghost, tsk);
	if (r)
		goto up_mmap_sem;

	r = export_mm_counters(action, ghost, mm, exported_mm);

up_mmap_sem:
	up_read(&mm->mmap_sem);
	if (r)
		goto out;

	if (action->type == EPM_CHECKPOINT) {
		r = export_process_pages(tsk->application, ghost, mm);
		if (r)
			goto out;
	}

out:
	return r;

exit_put_mm:
	if (exported_mm != mm)
		mmput(exported_mm);
	return r;
}



/*****************************************************************************/
/*                                                                           */
/*                              IMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

int import_vma_pages(ghost_t *ghost,
		     struct mm_struct *mm,
		     struct vm_area_struct *vma)
{
	void *page_addr;
	unsigned long address = 0;
	int nr_pages_received = 0;
	int nr_pages_sent;
	int page_excluded;
	pgd_t *pgd;
	pgprot_t prot;
	int r;

	BUG_ON(!vma);

	while (1) {
		struct page *new_page = NULL;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		r = ghost_read(ghost, &address, sizeof(unsigned long));
		if (r)
			goto err_read;

		if (address == 0)   /* We have reach the last VMA Page. */
			break;

		r = ghost_read(ghost, &prot, sizeof(pgprot_t));
		if (r)
			goto err_read;

		new_page = alloc_page(GFP_HIGHUSER);

		BUG_ON(!new_page);

		pgd = pgd_offset(mm, address);
		pud = pud_alloc(mm, pgd, address);
		pmd = pmd_alloc(mm, pud, address);
		BUG_ON(!pmd);

		pte = pte_alloc_map(mm, pmd, address);
		BUG_ON(!pte);
		set_pte (pte, mk_pte(new_page, prot));

		BUG_ON(unlikely(anon_vma_prepare(vma)));

		page_add_new_anon_rmap(new_page, vma, address);

		page_addr = kmap(new_page);

		r = ghost_read_type(ghost, page_excluded);
		if (r)
			goto err_read;

		if (!page_excluded) {
			r = ghost_read (ghost, page_addr, PAGE_SIZE);
			if (r)
				goto err_read;
		}

		nr_pages_received++;

		kunmap(new_page);
	}

	r = ghost_read(ghost, &nr_pages_sent, sizeof (int));

	BUG_ON(nr_pages_sent != nr_pages_received);

err_read:
	return r;
}

/** This function imports the physical memory pages of a process
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param ghost       Ghost where pages should be read from.
 *  @param mm          mm_struct to import memory pages in.
 *  @param incremental Tell whether or not the checkpoint is an incremental one
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_process_pages(struct epm_action *action,
			 ghost_t *ghost,
			 struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	int r = 0;

	BUG_ON(!mm);

	vma = mm->mmap;
	BUG_ON(!vma);

	while (vma) {

		if (vma->vm_ops != &special_mapping_vmops) {
			r = import_vma_pages(ghost, mm, vma);
			if (r)
				goto exit;
		}
		vma = vma->vm_next;
	}

	{
		int magic;

		r = ghost_read(ghost, &magic, sizeof(int));
		BUG_ON(!r && magic != 962134);
	}
exit:
	return r;
}



static inline void unmap_hole (struct mm_struct *mm,
			       unsigned long start,
			       unsigned long end)
{
	unsigned long total_vm, locked_vm;

	total_vm = mm->total_vm;
	locked_vm = mm->locked_vm;
	do_munmap (mm, start, end - start);
	mm->total_vm = total_vm;
	mm->locked_vm = locked_vm;
}



int reconcile_vmas(struct mm_struct *mm, struct vm_area_struct *vma,
		   unsigned long *last_end)
{
	struct vm_area_struct *old;
	int had_anon_vma = 0, r = 0;

	/* If the is a hole between the last imported VMA and the current one,
	 * unmap every in between.
	 */
	if (vma->vm_start != *last_end) {
		/// TODO: remove this deprecated code
		unmap_hole (mm, *last_end, vma->vm_start);
	}

	if (vma->anon_vma) {
		had_anon_vma = 1;
		vma->anon_vma = NULL;
	}

	old = find_vma(mm, vma->vm_start);

	/* Easy case: no conflict with existing VMA, just map the new VMA */
	if (!old || (old->vm_start >= vma->vm_end)) {
		r = insert_vm_struct (mm, vma);
		if (had_anon_vma)
			anon_vma_prepare(vma);
		goto done;
	}

#ifdef CONFIG_KRG_DEBUG
	/* Paranoia checks */
	BUG_ON ((old->vm_start != vma->vm_start) ||
		(old->vm_end != vma->vm_end));
	BUG_ON (old->vm_flags != vma->vm_flags);
	BUG_ON (old->vm_ops != vma->vm_ops);
	BUG_ON (old->vm_file && !vma->vm_file);
	BUG_ON (vma->vm_file && !old->vm_file);
	BUG_ON (old->vm_file && vma->vm_file &&
		(old->vm_file->f_dentry != vma->vm_file->f_dentry));
	BUG_ON ((old->vm_pgoff != vma->vm_pgoff) && vma->vm_file);
#endif

	remove_vma(vma);

	vma = old;
done:
	*last_end = vma->vm_end;

	return r;
}



/** Import one VMA from the ghost.
 *  @author  Geoffroy Vallee, Renaud Lottiaux
 *
 *  @param ghost    Ghost where data are be stored.
 *  @param tsk      The task to import the VMA to.
 *  @param vma      The VMA to import.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static int import_one_vma (struct epm_action *action,
			   ghost_t *ghost,
                           struct task_struct *tsk,
			   unsigned long *last_end,
			   hashtable_t *file_table)
{
	struct vm_area_struct *vma;
	krgsyms_val_t vm_ops_type, initial_vm_ops_type;
	int r;

	vma = kmem_cache_alloc (vm_area_cachep, GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	/* Import the vm_area_struct */
	r = ghost_read (ghost, vma, sizeof (struct vm_area_struct));
	if (r)
		goto err_vma;

	partial_init_vma(tsk->mm, vma);

#ifdef CONFIG_KRG_DVFS
	/* Import the associated file */
	r = import_vma_file (action, ghost, tsk, vma, file_table);
	if (r)
		goto err_vma;
#endif

	/* Import the vm_ops type of the vma */
	r = ghost_read (ghost, &vm_ops_type, sizeof (krgsyms_val_t));
	if (r)
		goto err_vm_ops;
	r = ghost_read (ghost, &initial_vm_ops_type, sizeof (krgsyms_val_t));
	if (r)
		goto err_vm_ops;

	vma->vm_ops = krgsyms_import (vm_ops_type);
	vma->initial_vm_ops = krgsyms_import (initial_vm_ops_type);

	BUG_ON (vma->vm_ops == &generic_file_vm_ops && vma->vm_file == NULL);

	if (action->type == EPM_REMOTE_CLONE
	    && !(action->remote_clone.clone_flags & CLONE_VM)) {
		check_link_vma_to_anon_memory_kddm_set (vma);
		vma->vm_flags &= ~VM_LOCKED;
	}

	if (action->type == EPM_CHECKPOINT)
		restore_initial_vm_ops(vma);

	if (vm_ops_type == KRGSYMS_VM_OPS_SPECIAL_MAPPING)
		import_vdso_context(vma);

	if (vma->vm_flags & VM_EXECUTABLE)
		added_exe_file_vma(vma->vm_mm);
	r = reconcile_vmas(tsk->mm, vma, last_end);
	if (r)
		goto err_reconcile;

exit:
	return r;

err_reconcile:
	if (vma->vm_flags & VM_EXECUTABLE)
		removed_exe_file_vma(vma->vm_mm);
err_vm_ops:
#ifdef CONFIG_KRG_DVFS
	if (vma->vm_file)
		fput(vma->vm_file);
#endif
err_vma:
	kmem_cache_free(vm_area_cachep, vma);
	goto exit;
}


static void file_table_fput(void *_file, void *data)
{
	struct file *file = _file;

	fput(file);
}


/** This function imports the list of VMA from the ghost
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be stored.
 *  @param tsk    Task to import vma data to.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static int import_vmas (struct epm_action *action,
			ghost_t *ghost,
			struct task_struct *tsk)
{
	unsigned long last_end = 0;
	hashtable_t *file_table;
	struct mm_struct *mm;
	int nr_vma = -1;
	int i, r;

	BUG_ON (tsk == NULL);

	file_table = hashtable_new (FILE_TABLE_SIZE);
	if (!file_table)
		return -ENOMEM;

	mm = tsk->mm;

	r = ghost_read(ghost, &nr_vma, sizeof(int));
	if (r)
		goto exit;

	for (i = 0; i < nr_vma; i++) {
		r = import_one_vma (action, ghost, tsk, &last_end, file_table);
		if (r)
			/* import_mm_struct will cleanup */
			goto exit;
	}

	if (last_end != TASK_SIZE)
		unmap_hole (mm, last_end, TASK_SIZE);

	flush_tlb_all ();

	{
		int magic = 0;

		r = ghost_read(ghost, &magic, sizeof(int));
		BUG_ON (!r && magic != 650874);
	}

exit:

	__hashtable_foreach_data(file_table, file_table_fput, NULL);

	hashtable_free(file_table);

	return r;
}



/** This function imports the context structure of a process
 *  @author Renaud Lottiaux
 *
 *  @param ghost  Ghost where data are stored.
 *  @param mm     MM context to import data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static int import_context_struct(ghost_t * ghost, struct mm_struct *mm)
{
	int r = 0;

#ifndef CONFIG_USERMODE

	if (mm->context.ldt) {
		int orig_size = mm->context.size;

		mm->context.ldt = NULL;
		mm->context.size = 0;

		r = alloc_ldt (&mm->context, orig_size, 0);
		if (r < 0)
			return r;

		r = ghost_read(ghost, mm->context.ldt,
			       mm->context.size * LDT_ENTRY_SIZE);
		if (r)
			goto exit;
	}

	mutex_init(&mm->context.lock);
#endif
exit:
	return r;
}

static int import_mm_counters(struct epm_action *action,
			      ghost_t *ghost,
			      struct mm_struct* mm)
{
	struct mm_struct *src_mm;
	int r;

	r = -ENOMEM;
	src_mm = allocate_mm();
	if (!src_mm)
		goto err;

	r = ghost_read(ghost, src_mm, sizeof(struct mm_struct));
	if (r)
		goto out_free_mm;

	mm->mmap_base = src_mm->mmap_base;
	mm->task_size = src_mm->task_size;
	mm->def_flags = src_mm->def_flags;
	mm->start_code = src_mm->start_code;
	mm->end_code = src_mm->end_code;
	mm->start_data = src_mm->start_data;
	mm->end_data = src_mm->end_data;
	mm->start_brk = src_mm->start_brk;
	mm->start_stack = src_mm->start_stack;
	mm->arg_start = src_mm->arg_start;
	mm->arg_end = src_mm->arg_end;
	mm->env_start = src_mm->env_start;
	mm->env_end = src_mm->env_end;
	mm->cached_hole_size = src_mm->cached_hole_size;
	mm->free_area_cache = src_mm->free_area_cache;
	mm->hiwater_rss = src_mm->hiwater_rss;
	mm->hiwater_vm = src_mm->hiwater_vm;
	mm->total_vm = src_mm->total_vm;
	mm->locked_vm = src_mm->locked_vm;
	mm->shared_vm = src_mm->shared_vm;
	mm->exec_vm = src_mm->exec_vm;
	mm->stack_vm = src_mm->stack_vm;
	mm->reserved_vm = src_mm->reserved_vm;
	mm->brk = src_mm->brk;
	mm->flags = src_mm->flags;

	r = ghost_read(ghost, &mm->mm_tasks, sizeof(atomic_t));

out_free_mm:
	free_mm(src_mm);
err:
	return r;
}

static int cr_link_to_mm_struct(struct epm_action *action,
				ghost_t *ghost,
				struct task_struct *tsk)
{
	int r;
	long key;
	struct mm_struct *mm;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto err;

	mm = get_imported_shared_object(action->restart.app,
					MM_STRUCT, key);

	if (!mm) {
		r = -E_CR_BADDATA;
		goto err;
	}

        /* the task is not yet hashed, no need to lock */
	atomic_inc(&mm->mm_users);

	tsk->mm = mm;
	tsk->active_mm = mm;

	r = import_mm_struct_end(mm, tsk);
err:
	return r;
}



static inline int do_import_mm_struct(struct epm_action *action,
				      ghost_t *ghost,
				      struct mm_struct **returned_mm)
{
	struct mm_struct *mm;
	unique_id_t mm_id;
	int r = 0;

	switch(action->type) {
	  case EPM_CHECKPOINT:
		  mm = allocate_mm();
		  if (!mm)
			  goto done;

		  r = ghost_read (ghost, mm, sizeof (struct mm_struct));
		  if (r)
			  goto exit_free_mm;

		  r = reinit_mm(mm);
		  if (r)
			  goto exit_free_mm;

		  atomic_set(&mm->mm_ltasks, 0);
		  mm->mm_id = 0;
		  mm->anon_vma_kddm_set = NULL;
		  mm->anon_vma_kddm_id = KDDM_SET_UNUSED;
		  break;

	  default:
		  r = ghost_read (ghost, &mm_id, sizeof (unique_id_t));
		  if (r)
			  return r;
		  mm = krg_get_mm(mm_id);
		  if (mm)
			  /* Reflect the belonging to the ghost task struct */
			  atomic_inc(&mm->mm_users);
	}

done:
	if (!mm)
		return -ENOMEM;

	*returned_mm = mm;

	return r;

exit_free_mm:
	free_mm(mm);
	return r;
}



/** This function imports the mm_struct of a process
 *  @author  Geoffroy Vallee, Renaud Lottiaux
 *
 *  @param ghost  Ghost where file data should be loaded from.
 *  @param tsk    Task to import file data in.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int import_mm_struct (struct epm_action *action,
		      ghost_t *ghost,
                      struct task_struct *tsk)
{
	struct mm_struct *mm = NULL;
	struct kddm_set *set;
	int r;

	if (action->type == EPM_CHECKPOINT
	    && action->restart.shared == CR_LINK_ONLY) {
		r = cr_link_to_mm_struct(action, ghost, tsk);
		return r;
	}

	r = do_import_mm_struct (action, ghost, &mm);
	if (r)
		return r;

	tsk->mm = mm;
	tsk->active_mm = mm;

	/* Import context */
	r = import_context_struct(ghost, mm);
	if (unlikely (r < 0))
		goto err;

	/* Just paranoia check */
	BUG_ON(mm->core_state);

#ifdef CONFIG_KRG_DVFS
	r = import_mm_exe_file(action, ghost, tsk);
	if (r)
		goto err;
#endif

	r = import_vmas (action, ghost, tsk);
	if (r < 0)
		goto err;

	r = import_mm_counters(action, ghost, mm);
	if (r)
		goto err;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	if (action->type == EPM_REMOTE_CLONE
	    && !(action->remote_clone.clone_flags & CLONE_VM))
		mm->locked_vm = 0;

	if (action->type == EPM_CHECKPOINT)
		r = import_process_pages(action, ghost, mm);
	else
		r = import_mm_struct_end(mm, tsk);

	if (r)
		goto err;

	set = mm->anon_vma_kddm_set;

	krg_put_mm (mm->mm_id);

	return 0;

err:
	krg_put_mm (mm->mm_id);
	unimport_mm_struct(tsk);
	return r;
}



void unimport_mm_struct(struct task_struct *task)
{
	free_ghost_mm(task);
}



static int cr_export_now_mm_struct(struct epm_action *action, ghost_t *ghost,
				   struct task_struct *task,
				   union export_args *args)
{
	int r;
	r = export_mm_struct(action, ghost, task);
	if (r)
		ckpt_err(action, r,
			 "Fail to save struct mm_struct of process %d",
			 task_pid_knr(task));
	return r;
}


static int cr_import_now_mm_struct(struct epm_action *action, ghost_t *ghost,
				   struct task_struct *fake, int local_only,
				   void **returned_data, size_t *data_size)
{
	int r;
	BUG_ON(*returned_data != NULL);

	r = import_mm_struct(action, ghost, fake);
	if (r) {
		ckpt_err(action, r,
			 "Fail to restore a struct mm_struct",
			 action->restart.app->app_id);
		goto err;
	}

	*returned_data = fake->mm;
err:
	return r;
}

static int cr_import_complete_mm_struct(struct task_struct *fake, void *_mm)
{
	struct mm_struct *mm = _mm;
	mmput(mm);

	return 0;
}

static int cr_delete_mm_struct(struct task_struct *fake, void *_mm)
{
	struct mm_struct *mm = _mm;
	mmput(mm);

	return 0;
}

struct shared_object_operations cr_shared_mm_struct_ops = {
        .export_now         = cr_export_now_mm_struct,
	.export_user_info   = NULL,
	.import_now         = cr_import_now_mm_struct,
	.import_complete    = cr_import_complete_mm_struct,
	.delete             = cr_delete_mm_struct,
};
