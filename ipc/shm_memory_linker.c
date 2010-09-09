/** KDDM shared memory linker.
 *  @file shm_memory_linker.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */

#include <linux/mm.h>
#include <linux/shm.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/string.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/mm_inline.h>
#include <linux/kernel.h>
#include <linux/swap.h>
#include <kddm/kddm.h>
#include "krgshm.h"
#include "ipc_handler.h"

extern int memory_first_touch (struct kddm_obj * obj_entry,
			       struct kddm_set * set, objid_t objid,int flags);

void memory_change_state (struct kddm_obj * objEntry, struct kddm_set * kddm,
			  objid_t objid, kddm_obj_state_t state);

extern int memory_remove_page (void *object,
			       struct kddm_set * kddm, objid_t objid);
extern int memory_alloc_object (struct kddm_obj * objEntry,
				struct kddm_set * kddm, objid_t objid);

extern int memory_import_object (struct rpc_desc *desc, struct kddm_set *set,
				 struct kddm_obj *objEntry, objid_t objid,
				 int flags);
extern int memory_export_object (struct rpc_desc *desc, struct kddm_set *set,
				 struct kddm_obj *objEntry, objid_t objid,
				 int flags);

extern void map_kddm_page (struct vm_area_struct *vma, unsigned long address,
			   struct page *page, int write);

/*****************************************************************************/
/*                                                                           */
/*                            SHM KDDM IO FUNCTIONS                          */
/*                                                                           */
/*****************************************************************************/



/** Insert a new shm memory page in the corresponding mapping.
 *  @author Renaud Lottiaux
 *
 *  @param  objEntry  Descriptor of the page to insert.
 *  @param  kddm      KDDM descriptor
 *  @param  padeid    Id of the page to insert.
 */
int shm_memory_insert_page(struct kddm_obj *objEntry, struct kddm_set *kddm,
			   objid_t objid)
{
	struct page *page;
	struct shmid_kernel *shp;
	struct address_space *mapping = NULL;
	int ret, shm_id;
	struct ipc_namespace *ns;

	ns = find_get_krg_ipcns();
	BUG_ON(!ns);

	shm_id = *(int *) kddm->private_data;

	shp = local_shm_lock(ns, shm_id);

	if (IS_ERR(shp)) {
		ret = PTR_ERR(shp);
		goto error;
	}

	mapping = shp->shm_file->f_dentry->d_inode->i_mapping;

	local_shm_unlock(shp);

	page = objEntry->object;
	page->index = objid;

	/* TODO: add the page in lru lists. This was done in a previous version
	 * but was leading to corruptions in LRU lists (bug seen with boinc or
	 * postgreSQL for instance).
	 */
	ret = add_to_page_cache(page, mapping, objid, GFP_ATOMIC);
	if (ret) {
		printk("shm_memory_insert_page: add_to_page_cache returns %d\n",
		       ret);
		BUG();
	}
	unlock_page(page);

error:
	put_ipc_ns(ns);

	return ret;
}



/** Invalidate a KDDM memory page.
 *  @author Renaud Lottiaux
 *
 *  @param  kddm     KDDM descriptor
 *  @param  objid    Id of the page to invalidate
 */
int shm_memory_invalidate_page (struct kddm_obj * objEntry,
				struct kddm_set * kddm,
				objid_t objid)
{
	int res ;

	if (objEntry->object) {
		struct page *page = (struct page *) objEntry->object;

		BUG_ON (page->mapping == NULL);
		BUG_ON (TestSetPageLocked(page));

		SetPageToInvalidate(page);
		res = try_to_unmap(page, 0);

		ClearPageToInvalidate(page);
		remove_from_page_cache (page);

		if (PageDirty(page)) {
			printk ("Check why the page is dirty...\n");
			ClearPageDirty(page);
		}
		unlock_page(page);

		page_cache_release (page);

#ifdef IPCDEBUG_PAGEALLOC
		int extra_count = 0;

		if (PageInVec(page))
			extra_count = 1;

		BUG_ON (page_mapcount(page) != 0);

		if ((page_count (page) != objEntry->countx + extra_count)) {
			WARNING ("Hum... page %p (%ld;%ld) has count %d;%d "
				 "(against %d)\n", page, kddm->id, objid,
				 page_count (page), page_mapcount(page),
				 objEntry->countx + extra_count);
		}

		if (PageActive(page)) {
			WARNING ("Hum. page %p (%ld;%ld) has Active bit set\n",
				 page, kddm->id, objid);
			while (1)
				schedule();
		}
#endif
	}

	return 0;
}



/** Handle a kddm set memory page remove.
 *  @author Renaud Lottiaux
 *
 *  @param  set      Kddm Set descriptor
 *  @param  padeid   Id of the page to remove
 */
int shm_memory_remove_page (void *object,
			    struct kddm_set * set,
			    objid_t objid)
{
	if (object)
		page_cache_release ((struct page *) object);

	return 0;
}



/****************************************************************************/

/* Init the memory IO linker */

struct iolinker_struct shm_memory_linker = {
	first_touch:       memory_first_touch,
	remove_object:     shm_memory_remove_page,
	invalidate_object: shm_memory_invalidate_page,
	change_state:      memory_change_state,
	insert_object:     shm_memory_insert_page,
	linker_name:       "shm",
	linker_id:         SHM_MEMORY_LINKER,
	alloc_object:      memory_alloc_object,
	export_object:     memory_export_object,
	import_object:     memory_import_object
};



/*****************************************************************************/
/*                                                                           */
/*                              SHM VM OPERATIONS                            */
/*                                                                           */
/*****************************************************************************/



/** Handle a nopage fault on an anonymous VMA.
 * @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param  vma           vm_area of the faulting address area
 *  @param  vmf
 */
int shmem_memory_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_dentry->d_inode;
	struct page *page;
	struct kddm_set *kddm;
	unsigned long address;
	objid_t objid;
	int write_access = vmf->flags & FAULT_FLAG_WRITE;

	address = (unsigned long)(vmf->virtual_address) & PAGE_MASK;

	kddm = inode->i_mapping->kddm_set;

	BUG_ON(!kddm);
	objid = vma->vm_pgoff + (address - vma->vm_start) / PAGE_SIZE;

	if (write_access)
		page = kddm_grab_object(kddm_def_ns, kddm->id, objid);
	else
		page = kddm_get_object(kddm_def_ns, kddm->id, objid);

	page_cache_get(page);

	if (!page->mapping) {
		printk ("Hum... NULL mapping in shmem_memory_nopage\n");
		page->mapping = inode->i_mapping;
	}

	map_kddm_page (vma, address, page, write_access);
	ClearPageMigratable(page);

	inc_mm_counter(vma->vm_mm, file_rss);
	page_add_file_rmap(page);

	kddm_put_object (kddm_def_ns, kddm->id, objid);

	vmf->page = page;
	return 0;
}

/** Handle a wppage fault on a memory KDDM set.
 *  @author Renaud Lottiaux
 *
 *  @param  vma       vm_area of the faulting address area
 *  @param  virtaddr  Virtual address of the page fault
 *  @return           Physical address of the page
 */
struct page *shmem_memory_wppage (struct vm_area_struct *vma,
				  unsigned long address,
				  struct page *old_page)
{
	struct inode *inode = vma->vm_file->f_dentry->d_inode;
	struct page *page;
	struct kddm_set *kddm;
	objid_t objid;

	BUG_ON(!vma);

	kddm = inode->i_mapping->kddm_set;

	BUG_ON(!kddm);
	objid = vma->vm_pgoff + (address - vma->vm_start) / PAGE_SIZE;

	page = kddm_grab_object (kddm_def_ns, kddm->id, objid);

	if (!page->mapping)
		page->mapping = inode->i_mapping;

	map_kddm_page (vma, address, page, 1);

	if (page != old_page) {
		page_add_file_rmap(page);
		page_cache_get(page);
	}

	kddm_put_object (kddm_def_ns, kddm->id, objid);

	return page;
}

/****************************************************************************/

/* Init the Kerrighed SHM file operations structure */

struct vm_operations_struct krg_shmem_vm_ops = {
	fault:	shmem_memory_fault,
	wppage:	shmem_memory_wppage,
};

/****************************************************************************/

static int krg_shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct shm_file_data *sfd;

	BUG_ON(!file->private_data); /*shm_file_data(file) */

	sfd = shm_file_data(file);
#ifdef CONFIG_KRG_DEBUG
	{
		struct ipc_namespace *ns;

		ns = find_get_krg_ipcns();
		BUG_ON(!ns);

		BUG_ON(sfd->ns != ns);

		put_ipc_ns(ns);
	}
#endif
        file_accessed(file);
	vma->vm_ops = &krg_shmem_vm_ops;
	vma->vm_flags |= VM_KDDM;

	return 0;
}

/* Init the Kerrighed SHM file operations structure */

struct file_operations krg_shm_file_operations = {
	.mmap = krg_shmem_mmap,
};
