/** Memory injection code.
 *  @file injection.c
 *
 *  Copyright (C) 2008, Renaud Lottiaux, Kerlabs.
 */
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/vmstat.h>
#include <linux/pagevec.h>
#include <linux/cpuset.h>
#include <linux/mm_inline.h>
#include <asm/tlbflush.h>
#include <linux/module.h>
#include <kerrighed/sys/types.h>

#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>
#include <kddm/kddm.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/dynamic_node_info_linker.h>
#include "injection.h"
#include "mm_struct.h"

kerrighed_node_t last_chosen_node = KERRIGHED_NODE_ID_NONE;

int node_mem_usage[KERRIGHED_MAX_NODES];
EXPORT_SYMBOL(node_mem_usage);
static atomic_t mem_usage_notified = ATOMIC_INIT(FREE_MEM);

struct tasklet_struct notify_tasklet;

unsigned long low_mem_limit;
unsigned long low_mem_limit_delta;

/*********************************** Policies ********************************/

kerrighed_node_t select_injection_node_ff(void)
{
       kerrighed_node_t start_node, node;
       int shrink_caches = 0;

       if (last_chosen_node == KERRIGHED_NODE_ID_NONE)
               start_node = krgnode_next_online_in_ring (kerrighed_node_id);
       else
               start_node = last_chosen_node;

       node = start_node;

retry:
       if ( (node_mem_usage[node] == FREE_MEM) ||
	    (shrink_caches && (node_mem_usage[node] == LOW_MEM))) {
	       last_chosen_node = node;
	       return node;
       }

       node = krgnode_next_online_in_ring (node);
       if (node == kerrighed_node_id)
	       node = krgnode_next_online_in_ring (node);
       if (node != start_node)
               goto retry;

       if (!shrink_caches) {
               shrink_caches = 1;
               goto retry;
       }

       return KERRIGHED_NODE_ID_NONE;
}


kerrighed_node_t select_injection_node_rr(void)
{
       kerrighed_node_t start_node, node;
       int shrink_caches = 0;

       if (last_chosen_node == KERRIGHED_NODE_ID_NONE)
               start_node = kerrighed_node_id;
       else
               start_node = last_chosen_node;

       node = krgnode_next_online_in_ring (start_node);
       if (node == kerrighed_node_id)
	       node = krgnode_next_online_in_ring (node);
retry:
       if ( (node_mem_usage[node] == FREE_MEM) ||
	    (shrink_caches && (node_mem_usage[node] == LOW_MEM))) {
	       last_chosen_node = node;
	       return node;
       }

       node = krgnode_next_online_in_ring (node);
       if (node == kerrighed_node_id)
	       node = krgnode_next_online_in_ring (node);
       if (node != start_node)
               goto retry;

       if (!shrink_caches) {
               shrink_caches = 1;
               goto retry;
       }

       return KERRIGHED_NODE_ID_NONE;
}


/************************** Low mem notify management ************************/


void handle_notify_low_mem (struct rpc_desc* desc,
			    void *msg,
			    size_t size)
{
	kerrighed_node_t nodeid = desc->client;
	int old_val;

	old_val = node_mem_usage[nodeid];
	node_mem_usage[nodeid] = *((int*)msg);

	switch (node_mem_usage[nodeid]) {
	  case FREE_MEM:
//		  printk ("## MEM NOTIFY - Node[%d] switched to FREE_MEM\n",
//			  nodeid);
		  if (old_val == OUT_OF_MEM)
			  rpc_disable_lowmem_mode(nodeid);
		  break;

	  case LOW_MEM:
//		  printk ("## MEM NOTIFY - Node[%d] switched to LOW_MEM\n",
//			  nodeid);
		  if (old_val == OUT_OF_MEM)
			  rpc_disable_lowmem_mode(nodeid);
		  break;

	  case OUT_OF_MEM:
//		  printk ("## MEM NOTIFY - Node[%d] switched to OUT_OF_MEM\n",
//			  nodeid);
		  rpc_enable_lowmem_mode(nodeid);
		  break;
	}
}



static void do_notify_mem(unsigned long unused)
{
	krgnodemask_t nodes;

	krgnodes_copy(nodes, krgnode_online_map);
	krgnode_clear(kerrighed_node_id, nodes);

	rpc_async_m(RPC_MM_NOTIFY_LOW_MEM, kddm_def_ns->rpc_comm, &nodes,
		    &mem_usage_notified, sizeof(mem_usage_notified));
}



void krg_notify_mem(int mem_usage)
{
	long free_pages, cache_pages;
	int old_val;

	if (mem_usage)
		goto set_mem_usage;

	free_pages = nr_free_pages();

	if (free_pages < low_mem_limit) {
		cache_pages = global_page_state(NR_FILE_PAGES)
			- total_swapcache_pages;
		/* - buffer_pages */

		if (cache_pages < low_mem_limit)
			mem_usage = OUT_OF_MEM;
		else
			if (atomic_read(&mem_usage_notified) != OUT_OF_MEM)
				mem_usage = LOW_MEM;
	}

	if (free_pages > low_mem_limit + low_mem_limit_delta)
		mem_usage = FREE_MEM;

	if (!mem_usage)
		return;

set_mem_usage:
	old_val = atomic_xchg(&mem_usage_notified, mem_usage);

	if (old_val == mem_usage)
		return;

	switch (mem_usage) {
	  case FREE_MEM:
//		  printk ("## MEM NOTIFY - Switch local node to FREE_MEM\n");
		  if (old_val == OUT_OF_MEM)
			  rpc_disable_local_lowmem_mode();
		  break;

	  case LOW_MEM:
//		  printk ("## MEM NOTIFY - Switch local node to LOW_MEM\n");
		  if (old_val == OUT_OF_MEM)
			  rpc_disable_local_lowmem_mode();
		  break;

	  case OUT_OF_MEM:
//		  printk ("## MEM NOTIFY - Switch local node to OUT_OF_MEM\n");
		  rpc_enable_local_lowmem_mode();
		  break;
	}

	tasklet_hi_schedule(&notify_tasklet);
}



/************************** KDDM shrinker ************************/

static int flush_page(struct page *page,
		      struct mm_struct *mm,
		      objid_t objid,
		      pte_t *pte,
		      spinlock_t *ptl)
{
	struct kddm_set *set = mm->anon_vma_kddm_set;
	kerrighed_node_t dest_node;
	int r = SWAP_FAIL;

	pte_unmap_unlock(pte, ptl);

	/* Check if the KDDM has not been destroyed since the page selection */
	if (mm->anon_vma_kddm_set == NULL)
		return SWAP_FAIL;

	/* mm_id == 0 means the mm is being freed */
	if (mm->mm_id == 0)
		return SWAP_FAIL;

	if (PageMigratable(page))
		dest_node = select_injection_node_rr();
	else
		dest_node = KERRIGHED_NODE_ID_NONE;

	SetPageSwapCache(page);
	r = _kddm_flush_object(set, objid, dest_node);
	ClearPageSwapCache(page);

	if (r) {
		if ((r == -ENOSPC) && (dest_node == KERRIGHED_NODE_ID_NONE))
			return SWAP_FLUSH_FAIL;
		else
			return SWAP_FAIL;
	}
	else
		ClearPageMigratable(page);


	return SWAP_SUCCESS;
}



static int try_to_flush_one(struct page *page, struct vm_area_struct *vma)
{
        struct mm_struct *mm = vma->vm_mm;
        unsigned long address;
	objid_t objid;
        pte_t *pte;
        spinlock_t *ptl;
        int ret = SWAP_AGAIN;

	objid = page->index;
	if (vma->vm_file)
		objid += (vma->vm_start >> PAGE_SHIFT) - vma->vm_pgoff;

        address = objid * PAGE_SIZE;

        pte = page_check_address(page, mm, address, &ptl, 0);
        if (!pte)
		return ret;

        /*
         * If the page is mlock()d, we cannot swap it out.
         * If it's recently referenced (perhaps page_referenced
         * skipped over this mm) then we should reactivate it.
         */
        if (((vma->vm_flags & VM_LOCKED) ||
	     (ptep_clear_flush_young(vma, address, pte)))) {
		pte_unmap_unlock(pte, ptl);
		return SWAP_FAIL;
	}

	return flush_page(page, mm, objid, pte, ptl);
}



int try_to_flush_page(struct page *page)
{
        struct anon_vma *anon_vma;
        struct vm_area_struct *vma;
	int ret = SWAP_AGAIN;

	krg_notify_mem(OUT_OF_MEM);

	anon_vma = page_lock_anon_vma(page);
        if (!anon_vma)
                return SWAP_AGAIN;

	list_for_each_entry(vma, &anon_vma->head, anon_vma_node) {
		if (page_mapcount(page) <= 1)
			break;
		ret = try_to_unmap_one(page, vma, 0);
		if (ret == SWAP_FAIL)
			goto exit;
	}

	page_unlock_anon_vma(anon_vma);

	if (page_mapcount(page) == 1)
		ret = try_to_flush_one(page, vma);

exit:
	return ret;
}



/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/



static inline void init_low_mem_limit(void)
{
	struct zone *zone;

	low_mem_limit = 0;

	for_each_zone(zone) {
		low_mem_limit += zone->pages_low;
	}

	low_mem_limit *= 2;
	low_mem_limit_delta = low_mem_limit;
}



void mm_injection_init (void)
{
	int i;

	tasklet_init(&notify_tasklet, do_notify_mem, 0);

	init_low_mem_limit();

	rpc_register_void(RPC_MM_NOTIFY_LOW_MEM, handle_notify_low_mem, 0);

	for (i = 0; i < KERRIGHED_MAX_NODES; i++)
		node_mem_usage[i] = FREE_MEM;
}



void mm_injection_finalize (void)
{
}

