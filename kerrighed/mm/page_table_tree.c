/** KDDM page table tree management.
 *  @file page_table_tree.c
 *
 *  Copyright (C) 2008, Renaud Lottiaux, Kerlabs.
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>

#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

#include "page_table_tree.h"
#include "memory_int_linker.h"
#include "mm_struct.h"
#include "vma_struct.h"

/*****************************************************************************/
/*                                                                           */
/*                             HELPER FUNCTIONS                              */
/*                                                                           */
/*****************************************************************************/



/* Used to ensure atomicity of operations on kddm_count and obj_entry fields */
static inline void wait_lock_kddm_page (struct page *page)
{
       while (TestSetPageLockedKDDM(page))
		cpu_relax();
}

static inline void unlock_kddm_page (struct page *page)
{
	ClearPageLockedKDDM(page);
}



static inline void page_put_kddm_count(struct kddm_set *set,
				       struct page *page)
{
	struct kddm_obj *obj_entry = page->obj_entry;

	BUG_ON(obj_entry == NULL);

	if (!atomic_dec_and_test(&page->_kddm_count))
		return;

	/* Kill obj_entry->object field to avoid removal in IO linker.
	 * Such removal would lead to a double page free...
	 */
	obj_entry->object = NULL;
	BUG_ON(TEST_OBJECT_LOCKED(obj_entry));
	free_kddm_obj_entry(set, obj_entry, page->index);
	page->obj_entry = NULL;
}



static inline void unmap_page(struct mm_struct *mm,
			      unsigned long addr,
			      struct page *page,
			      pte_t *ptep)
{
	pte_clear(mm, addr, ptep);

	update_hiwater_rss(mm);

	if (PageAnon(page))
		dec_mm_counter(mm, anon_rss);
	else
		dec_mm_counter(mm, file_rss);

	page_remove_rmap(page);
}



/* The ZERO_PAGE is considered as a file page but not linked to any file.
 * Moreover, this page is not linked to any mapping.
 * Managing this page would introduce too much particular cases.
 */
static inline struct page *replace_zero_page(struct mm_struct *mm,
					     struct vm_area_struct *vma,
					     struct page *page,
					     pte_t *ptep,
					     unsigned long addr)
{
	struct page *new_page;

	new_page = alloc_page_vma(GFP_HIGHUSER | __GFP_ZERO, vma, addr);
	if (!new_page)
		return NULL;

	BUG_ON (TestSetPageLockedKDDM(new_page));

	unmap_page (mm, addr, page, ptep);

	set_pte (ptep, mk_pte (new_page, vma->vm_page_prot));
	page_add_anon_rmap(new_page, vma, addr);
	inc_mm_counter(mm, anon_rss);

	return new_page;
}



static inline struct kddm_obj *init_pte(struct mm_struct *mm,
					pte_t *ptep,
					struct kddm_set *set,
					objid_t objid,
					struct vm_area_struct *vma,
					struct kddm_obj *obj_entry)
{
	struct page *page = NULL, *new_page;
	int obj_entry_used = 0;

	if (!pte_present(*ptep))
		return obj_entry;

	page = pfn_to_page(pte_pfn(*ptep));

	wait_lock_kddm_page(page);

	if (!PageAnon(page)) {
		if (!(page == ZERO_PAGE(NULL)))
			goto done;
		new_page = replace_zero_page(mm, vma, page, ptep,
					     objid * PAGE_SIZE);
		/* new_page is returned locked */
		unlock_kddm_page(page);
		page = new_page;
	}

	atomic_inc (&page->_kddm_count);
	if (page->obj_entry != NULL)
		goto done;

	if (!obj_entry) {
		obj_entry = alloc_kddm_obj_entry(set, objid);
		if (!obj_entry)
			BUG();
	}
	else {
		change_prob_owner(obj_entry,
				  kddm_io_default_owner(set, objid));
		obj_entry_used = 1;
	}

	BUG_ON (kddm_io_default_owner(set, objid) != kerrighed_node_id);
	obj_entry->object = page;
	kddm_change_obj_state(set, obj_entry, objid, WRITE_OWNER);

	BUG_ON (page->obj_entry != NULL);

	page->obj_entry = obj_entry;
done:
	unlock_kddm_page(page);

	if (obj_entry_used)
		return NULL;
	else
		return obj_entry;
}



static inline struct kddm_obj *get_obj_entry_from_pte(struct mm_struct *mm,
						      unsigned long addr,
						      pte_t *ptep,
						      struct kddm_obj *new_obj)
{
	struct kddm_obj *obj_entry = NULL;
	struct page *page;

        if (pte_present(*ptep)) {
		page = pfn_to_page(pte_pfn(*ptep));
		BUG_ON(!page);

		if (!PageAnon(page)) {
			if (new_obj) {
				unmap_page (mm, addr, page, ptep);
				set_pte_obj_entry(ptep, new_obj);
			}
			return new_obj;
		}

		if (new_obj) {
			if (page->obj_entry != NULL)
				printk ("WARN: entry %p in page %p\n",
					page->obj_entry, page);
			if (page->obj_entry == NULL) {
				atomic_inc(&page->_kddm_count);
				page->obj_entry = new_obj;
			}
		}
		obj_entry = page->obj_entry;
	}
	else {
		if ((pte_val(*ptep) == 0) && new_obj)
			set_pte_obj_entry(ptep, new_obj);

		if (pte_obj_entry(ptep))
			obj_entry = get_pte_obj_entry(ptep);
	}

	return obj_entry;
}



static inline pte_t *kddm_pt_lookup_pte (struct mm_struct *mm,
					 unsigned long objid,
					 spinlock_t **ptl)
{
	unsigned long address = objid * PAGE_SIZE;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, address);
	pud = pud_offset(pgd, address);
	if (pud_none(*pud) || unlikely(pud_bad(*pud)))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)))
		return NULL;

	pte = pte_offset_map_lock(mm, pmd, address, ptl);
	if (!pte)
		pte_unmap_unlock(ptep, *ptl);

	return pte;
}



/** Lookup for an obj entry stored a page table tree.
 *  @param mm        The memory structure the object is stored in.
 *  @param objid     The objid of the object to lookup.
 *
 *  @return The data if found.
 *          NULL if the data is not found.
 */
static inline void *kddm_pt_lookup (struct mm_struct *mm,
				    unsigned long objid)
{
	struct kddm_obj *obj_entry;
	spinlock_t *ptl;
	pte_t *ptep;

	ptep = kddm_pt_lookup_pte (mm, objid, &ptl);
	if (!ptep)
		return NULL;

	obj_entry = get_obj_entry_from_pte(mm, objid * PAGE_SIZE, ptep, NULL);

	pte_unmap_unlock(ptep, ptl);

	return obj_entry;
}



static inline void __pt_for_each_pte(struct kddm_set *set,
				     struct mm_struct *mm, pmd_t *pmd,
				     unsigned long start, unsigned long end,
				     int(*f)(unsigned long, void*, void*),
				     void *priv)
{
	struct kddm_obj *obj_entry, *new_obj = NULL;
	unsigned long addr;
	spinlock_t *ptl;
	pte_t *ptep;

	/* Pre-allocate obj_entry to avoid allocation when holding
	 * mm->page_table_lock (gotten by pte_offset_map_lock).
	 * This lock being taken during page swap, we can face a recursive
	 * lock if the kernel have to free memory during obj_entry allocaton.
	 */
	if (!f)
		new_obj = alloc_kddm_obj_entry(set, 0);

	ptep = pte_offset_map_lock(mm, pmd, start, &ptl);

	for (addr = start; addr != end; addr += PAGE_SIZE) {
		if (f) {
retry:
			obj_entry = get_obj_entry_from_pte(mm, addr, ptep,
							   NULL);
			if (obj_entry &&
			    TEST_AND_SET_OBJECT_LOCKED (obj_entry)) {
				while (TEST_OBJECT_LOCKED (obj_entry))
					cpu_relax();
				goto retry;
			}
			if (obj_entry) {
				f(addr / PAGE_SIZE, obj_entry, priv);
				CLEAR_OBJECT_LOCKED (obj_entry);
			}
		}
		else {
			new_obj = init_pte(mm, ptep, set, addr / PAGE_SIZE,
			priv,new_obj);

			/* The object has been used, allocate a new one */
			if (!new_obj) {
				pte_unmap_unlock(ptep, ptl);
				new_obj = alloc_kddm_obj_entry(set, 0);
				ptep = pte_offset_map_lock(mm, pmd, addr,&ptl);
			}
		}

		ptep++;
	}
	pte_unmap_unlock(ptep - 1, ptl);

	if (new_obj)
		free_kddm_obj_entry(set, new_obj, 0);
}

static inline void __pt_for_each_pmd(struct kddm_set *set,
				     struct mm_struct *mm, pud_t *pud,
				     unsigned long start, unsigned long end,
				     int(*f)(unsigned long, void*, void*),
				     void *priv)
{
	unsigned long addr, next;
	pmd_t *pmd;

	pmd = pmd_offset(pud, start);

	for (addr = start; addr != end; addr = next) {
		next = pmd_addr_end(addr, end);
		if (pmd_present(*pmd))
			__pt_for_each_pte(set, mm, pmd, addr, next, f, priv);
		pmd++;
	}
}

static inline void __pt_for_each_pud(struct kddm_set *set,
				     struct mm_struct *mm, pgd_t *pgd,
				     unsigned long start, unsigned long end,
				     int(*f)(unsigned long, void*, void*),
				     void *priv)
{
	unsigned long addr, next;
	pud_t *pud;

	pud = pud_offset(pgd, start);

	for (addr = start; addr != end; addr = next) {
		next = pud_addr_end(addr, end);
		if (pud_present(*pud))
			__pt_for_each_pmd(set, mm, pud, addr, next, f, priv);
		pud++;
	}
}

static void kddm_pt_for_each(struct kddm_set *set, struct mm_struct *mm,
			     unsigned long start, unsigned long end,
			     int(*f)(unsigned long, void*, void*),
			     void *priv)
{
	unsigned long addr, next;
	pgd_t *pgd;

	pgd = pgd_offset(mm, start);

	for (addr = start; addr != end; addr = next) {
		next = pgd_addr_end(addr, end);
		if (pgd_present(*pgd))
			__pt_for_each_pud(set, mm, pgd, addr, next, f, priv);
		pgd++;
	}
}



int kddm_pt_invalidate (struct kddm_set *set,
			objid_t objid,
			struct kddm_obj *obj_entry,
			struct page *page)
{
	struct mm_struct *mm = set->obj_set;
	spinlock_t *ptl;
	pte_t *ptep;

	ptep = get_locked_pte(mm, objid * PAGE_SIZE, &ptl);
	if (!ptep)
		return -ENOMEM;

	if (!pte_present(*ptep))
		goto done;

	BUG_ON((pfn_to_page(pte_pfn(*ptep)) != NULL) &&
	       (pfn_to_page(pte_pfn(*ptep)) != page));

	if (atomic_dec_and_test(&page->_kddm_count))
		page->obj_entry = NULL;

	unmap_page(mm, objid * PAGE_SIZE, page, ptep);

	set_pte_obj_entry(ptep, obj_entry);

done:
	pte_unmap_unlock(ptep, ptl);

	return 0;
}



/*****************************************************************************/
/*                                                                           */
/*                             KDDM SET OPERATIONS                           */
/*                                                                           */
/*****************************************************************************/



static inline void check_create_vma(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(mm, addr);
	if (vma && (vma->vm_start <= addr))
		return;

	addr = addr & PAGE_MASK;

	alloc_fake_vma (mm, addr, addr + PAGE_SIZE);
}



static struct kddm_obj *kddm_pt_lookup_obj_entry (struct kddm_set *set,
						  objid_t objid)
{
	struct mm_struct *mm = set->obj_set;

	return kddm_pt_lookup(mm, objid);
}



static struct kddm_obj *kddm_pt_get_obj_entry (struct kddm_set *set,
					       objid_t objid,
					       struct kddm_obj *new_obj)
{
	struct mm_struct *mm = set->obj_set;
	struct kddm_obj *obj_entry;
	spinlock_t *ptl;
	pte_t *ptep;

	ptep = get_locked_pte(mm, objid * PAGE_SIZE, &ptl);
	if (!ptep)
		return ERR_PTR(-ENOMEM);

	obj_entry = get_obj_entry_from_pte(mm, objid * PAGE_SIZE, ptep,
					   new_obj);

	pte_unmap_unlock(ptep, ptl);

	if (obj_entry == new_obj)
		check_create_vma(mm, objid * PAGE_SIZE);

	return obj_entry;
}



static inline void __kddm_pt_insert_object(struct mm_struct *mm,
					   struct page *page,
					   unsigned long addr,
					   pte_t *ptep,
					   struct kddm_obj *obj_entry)
{
	pte_t entry;

	if (page) {
		entry = mk_pte(page, vm_get_page_prot(VM_READ));
		set_pte_at(mm, addr, ptep, entry);
		page->obj_entry = obj_entry;
		atomic_inc(&page->_kddm_count);
		inc_mm_counter(mm, anon_rss);
		__SetPageUptodate(page);
	}
	else
		set_pte_obj_entry(ptep, obj_entry);
}



static inline void add_page_anon_rmap (struct mm_struct *mm,
				       struct page *page,
				       unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(mm, addr);
	BUG_ON(!vma);
	if ((vma->anon_vma == NULL) && unlikely(anon_vma_prepare(vma)))
		BUG();

	page_add_new_anon_rmap(page, vma, addr);
}



static void kddm_pt_insert_object(struct kddm_set * set,
				  objid_t objid,
				  struct kddm_obj *obj_entry)
{
	struct mm_struct *mm = set->obj_set;
	spinlock_t *ptl;
	pte_t *ptep;
	struct page *page = obj_entry->object;

	BUG_ON(!page);
	BUG_ON(page->obj_entry && page->obj_entry != obj_entry);

	/* Insert the object in the page table */
	ptep = get_locked_pte(mm, objid * PAGE_SIZE, &ptl);
	if (!ptep)
		BUG();

	__kddm_pt_insert_object (mm, page, objid * PAGE_SIZE, ptep, obj_entry);

	pte_unmap_unlock(ptep, ptl);

	add_page_anon_rmap (mm, page, objid * PAGE_SIZE);
}



struct kddm_obj *kddm_pt_break_cow_object(struct kddm_set *set,
				    struct kddm_obj *obj_entry, objid_t objid,
				    int break_type)
{
	struct page *new_page = NULL, *old_page = obj_entry->object;
	struct mm_struct *mm = set->obj_set;
	struct kddm_obj *new_obj;
	unsigned long addr = objid * PAGE_SIZE;
	spinlock_t *ptl;
	pte_t *ptep;

	if (!old_page)
		return obj_entry;

	BUG_ON(page_kddm_count(old_page) == 0);
	BUG_ON(!TEST_OBJECT_LOCKED(obj_entry));

	wait_lock_kddm_page(old_page);
	if (page_kddm_count(old_page) == 1) {
		if (page_mapcount(old_page) == 1) {
			/* Page not shared, nothing to do */
			unlock_kddm_page(old_page);
			return obj_entry;
		}
		else {
			/* Page shared with a regular MM, no KDDM COW but a
			 * regular page COW is needed. Reuse the obj entry. */
			atomic_dec(&old_page->_kddm_count);
			old_page->obj_entry = NULL;
			unlock_kddm_page(old_page);
			new_obj = obj_entry;
		}
	}
	else {
		/* Page shared with another KDDM. COW the obj entry */
		BUG_ON(atomic_dec_and_test(&old_page->_kddm_count));
		new_obj = dup_kddm_obj_entry(obj_entry);
		CLEAR_OBJECT_LOCKED(obj_entry);
		unlock_kddm_page(old_page);
	}

	if (break_type == KDDM_BREAK_COW_COPY) {
		new_page = alloc_page (GFP_ATOMIC);
		if (new_page == NULL)
			return ERR_PTR(-ENOMEM);

		copy_user_highpage(new_page, old_page, addr, NULL);
	}

	new_obj->object = new_page;

	SET_OBJECT_LOCKED(new_obj);

	ptep = get_locked_pte(mm, addr, &ptl);
	BUG_ON (!ptep);
	BUG_ON (!pte_present(*ptep));

	/* Unmap old page and map the new one in the set mm */

	unmap_page (mm, addr, old_page, ptep);

	__kddm_pt_insert_object (mm, new_page, addr, ptep, new_obj);

	pte_unmap_unlock(ptep, ptl);

	if (new_page)
		add_page_anon_rmap (mm, new_page, addr);

	page_cache_release (old_page);

	return new_obj;
}



static void kddm_pt_remove_obj_entry (struct kddm_set *set,
				      objid_t objid)
{
	struct mm_struct *mm = set->obj_set;
	struct kddm_obj *obj_entry;
	spinlock_t *ptl = NULL;
	struct page *page;
	pte_t *ptep;

	ptep = kddm_pt_lookup_pte (mm, objid, &ptl);
	if (!ptep)
		return;

	if (!pte_present(*ptep)) {
		pte_clear(mm, objid * PAGE_SIZE, ptep);
		goto done;
	}

	obj_entry = get_obj_entry_from_pte(mm, objid * PAGE_SIZE, ptep, NULL);
	page = obj_entry->object;

	if (atomic_dec_and_test(&page->_kddm_count))
		page->obj_entry = NULL;

	unmap_page(mm, objid * PAGE_SIZE, page, ptep);
done:
	pte_unmap_unlock(ptep, ptl);
}



static void kddm_pt_for_each_obj_entry(struct kddm_set *set,
				       int(*f)(unsigned long, void *, void*),
				       void *data)
{
	struct mm_struct *mm = set->obj_set;

	BUG_ON(!f);

	spin_lock(&mm->page_table_lock);
	kddm_pt_for_each(set, mm, 0, PAGE_OFFSET, f, data);
	spin_unlock(&mm->page_table_lock);
}



static void kddm_pt_export (struct rpc_desc* desc, struct kddm_set *set)
{
	struct mm_struct *mm = set->obj_set;

	krgnode_set (desc->client, mm->copyset);

	rpc_pack_type(desc, mm->mm_id);
}



static void *kddm_pt_import (struct rpc_desc* desc, int *free_data)
{
	struct mm_struct *mm = NULL;
	unique_id_t mm_id;

	rpc_unpack_type (desc, mm_id);
	*free_data = 0;

	if (mm_id)
		mm = _kddm_find_object_raw (mm_struct_kddm_set, mm_id);

	return mm;
}

static inline void init_kddm_pt(struct kddm_set *set,
				struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	if (mm == NULL)
		return;

	for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
		if (anon_vma(vma))
			kddm_pt_for_each(set, mm, vma->vm_start, vma->vm_end,
					 NULL, vma);
	}
}

static void *kddm_pt_alloc (struct kddm_set *set, void *_data)
{
	struct mm_struct *mm = _data;

	if (mm == NULL) {
		mm = alloc_fake_mm(NULL);

		if (!mm)
			return NULL;
	}
	else
		atomic_inc(&mm->mm_users);

	init_kddm_pt(set, mm);

	set_anon_vma_kddm_set(mm, set);

	return mm;
}



static void kddm_pt_free (void *tree,
			  int (*f)(unsigned long, void *data, void *priv),
			  void *priv)
{
	struct mm_struct *mm = tree;

	mmput(mm);
}



/* Call-back called when mapping a page coming from swap */
void kcb_fill_pte(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	struct vm_area_struct *vma;

	vma = find_vma (mm, addr);
	BUG_ON ((vma == NULL) || (addr < vma->vm_start));

	init_pte(mm, ptep, mm->anon_vma_kddm_set, addr / PAGE_SIZE, vma, NULL);
}

/* Call-back called during page table destruction for each valid pte */
void kcb_zap_pte(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	struct kddm_set *set = mm->anon_vma_kddm_set;
	struct kddm_obj *obj_entry;
	struct page *page;

	BUG_ON(!set);

	obj_entry = get_obj_entry_from_pte(mm, addr, ptep, NULL);

	if (!obj_entry)
		return;

	if (pte_obj_entry(ptep)) {
		BUG_ON(TEST_OBJECT_LOCKED(obj_entry));
		free_kddm_obj_entry(set, obj_entry, addr / PAGE_SIZE);
		pte_clear(mm, addr, ptep);
	}
	else {
		page = (struct page *) obj_entry->object;
		BUG_ON(!page);

		wait_lock_kddm_page(page);
		page_put_kddm_count(set, page);
		unlock_kddm_page(page);
	}
}



struct kddm_set_ops kddm_pt_set_ops = {
	obj_set_alloc:       kddm_pt_alloc,
	obj_set_free:        kddm_pt_free,
	lookup_obj_entry:    kddm_pt_lookup_obj_entry,
	get_obj_entry:       kddm_pt_get_obj_entry,
	insert_object:       kddm_pt_insert_object,
	break_cow:           kddm_pt_break_cow_object,
	remove_obj_entry:    kddm_pt_remove_obj_entry,
	for_each_obj_entry:  kddm_pt_for_each_obj_entry,
	export:              kddm_pt_export,
	import:              kddm_pt_import,
};
