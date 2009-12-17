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

#include "debug_keripc.h"

#define MODULE_NAME "Shm Mem linker  "

#ifdef SHM_MEM_LINKER_DEBUG
#define DEBUG_THIS_MODULE
#endif

extern int memory_first_touch (struct kddm_obj * obj_entry,
			       struct kddm_set * set, objid_t objid,int flags);

void memory_change_state (struct kddm_obj * objEntry, struct kddm_set * kddm,
			  objid_t objid, kddm_obj_state_t state);

extern int memory_remove_page (void *object,
			       struct kddm_set * kddm, objid_t objid);
extern int memory_alloc_object (struct kddm_obj * objEntry,
				struct kddm_set * kddm, objid_t objid);

extern int memory_import_object (struct rpc_desc *desc, struct kddm_set *set,
				 struct kddm_obj *objEntry, objid_t objid);
extern int memory_export_object (struct rpc_desc *desc, struct kddm_set *set,
				 struct kddm_obj *objEntry, objid_t objid);

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

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "Insert page %p (%d;%ld;%ld) count"
	       " %d\n", objEntry->object, kddm->ns->id, kddm->id, objid,
	       page_count(objEntry->object));

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
	ret = add_to_page_cache_lru(page, mapping, objid, GFP_ATOMIC);
	if (ret) {
		printk("shm_memory_insert_page: add_to_page_cache_lru returns %d\n",
		       ret);
		BUG();
	}
	unlock_page(page);

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "Insert page (%ld;%ld) %p (@ %p) : "
	       "done (count = %d)\n", kddm->id, objid, page,
	       page_address(page), page_count (page));

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

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "Invalidate page (%ld;%ld)\n",
	       kddm->id, objid);

	if (objEntry->object) {
		struct page *page = (struct page *) objEntry->object;
		IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "Page (%ld;%ld) (count = "
		       "%d;%d) - flags : 0x%08lx\n", kddm->id, objid,
		       page_count (page), page_mapcount(page), page->flags);

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

		if (TestClearPageLRU(page))
			del_page_from_lru(page_zone(page), page);

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

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "Invalidate page (%ld;%ld) : done\n",
	       kddm->id, objid);

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
	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "remove page (%ld;%ld)\n", set->id,
	       objid);

	if (object)
		page_cache_release ((struct page *) object);

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 3, "remove page (%ld;%ld) : done\n",
	       set->id, objid);

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

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 1, "no page activated at 0x%08lx for "
	       "process %s (%d - %p). Access : %d in vma [0x%08lx:0x%08lx] "
		  "(0x%08lx) - file: 0x%p, anon_vma : 0x%p\n", (unsigned long) vmf->virtual_address,
	       current->comm, task_pid_knr(current), current, write_access,
	       vma->vm_start, vma->vm_end, (unsigned long) vma, vma->vm_file,
	       vma->anon_vma);

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
	ClearPageInjectable(page);

	inc_mm_counter(vma->vm_mm, file_rss);
	page_add_file_rmap(page);

	kddm_put_object (kddm_def_ns, kddm->id, objid);

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 4, "Done: page (%ld;%ld) at %p "
	       "(count %d;%d) - mapping %p (anon : %d)\n", kddm->id, objid,
	       page, page_count (page), page_mapcount(page), page->mapping,
	       PageAnon(page));

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

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 1, "wp page activated at 0x%08lx in"
	       "vma [0x%08lx:0x%08lx] (0x%08lx)\n", address,
	       vma->vm_start, vma->vm_end, (long) vma);

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

	IPCDEBUG (DBG_KERIPC_PAGE_FAULTS, 1, "Done : page at 0x%p has count %d/%d"
	       "\n", page, page_count (page), page_mapcount (page));

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

	IPCDEBUG(DBG_KERIPC_SHM_MAP, 2, "mmap shm %ld to vma [0x%08lx:0x%08lx]\n",
	      file->f_dentry->d_inode->i_ino, vma->vm_start, vma->vm_end);

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

	IPCDEBUG(DBG_KERIPC_SHM_MAP, 2, "mmap to vma [0x%08lx:0x%08lx] : done\n",
	      vma->vm_start, vma->vm_end);

	return 0;
}

/* Init the Kerrighed SHM file operations structure */

struct file_operations krg_shm_file_operations = {
	.mmap = krg_shmem_mmap,
};
