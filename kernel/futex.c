/*
 *  Fast Userspace Mutexes (which I call "Futexes!").
 *  (C) Rusty Russell, IBM 2002
 *
 *  Generalized futexes, futex requeueing, misc fixes by Ingo Molnar
 *  (C) Copyright 2003 Red Hat Inc, All Rights Reserved
 *
 *  Removed page pinning, fix privately mapped COW pages and other cleanups
 *  (C) Copyright 2003, 2004 Jamie Lokier
 *
 *  Robust futex support started by Ingo Molnar
 *  (C) Copyright 2006 Red Hat Inc, All Rights Reserved
 *  Thanks to Thomas Gleixner for suggestions, analysis and fixes.
 *
 *  PI-futex support started by Ingo Molnar and Thomas Gleixner
 *  Copyright (C) 2006 Red Hat, Inc., Ingo Molnar <mingo@redhat.com>
 *  Copyright (C) 2006 Timesys Corp., Thomas Gleixner <tglx@timesys.com>
 *
 *  PRIVATE futexes by Eric Dumazet
 *  Copyright (C) 2007 Eric Dumazet <dada1@cosmosbay.com>
 *
 *  Thanks to Ben LaHaise for yelling "hashed waitqueues" loudly
 *  enough at me, Linus for the original (flawed) idea, Matthew
 *  Kirkwood for proof-of-concept implementation.
 *
 *  "The futexes are also cursed."
 *  "But they come in a choice of three flavours!"
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/futex.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#ifdef CONFIG_KRG_EPM
#include <linux/pid_namespace.h>
#include <kddm/kddm.h>
#include <kerrighed/pid.h>
#include <kerrighed/krgsyms.h>
#include <net/krgrpc/rpc.h>
#endif

#include <asm/futex.h>

#include "rtmutex_common.h"

#ifdef CONFIG_KRG_EPM
static struct kddm_set *futex_kddm_set;
#endif

int __read_mostly futex_cmpxchg_enabled;

#define FUTEX_HASHBITS (CONFIG_BASE_SMALL ? 4 : 8)

/*
 * Priority Inheritance state:
 */
struct futex_pi_state {
	/*
	 * list of 'owned' pi_state instances - these have to be
	 * cleaned up in do_exit() if the task exits prematurely:
	 */
	struct list_head list;

	/*
	 * The PI object:
	 */
	struct rt_mutex pi_mutex;

	struct task_struct *owner;
	atomic_t refcount;

	union futex_key key;
};

/*
 * We use this hashed waitqueue instead of a normal wait_queue_t, so
 * we can wake only the relevant ones (hashed queues may be shared).
 *
 * A futex_q has a woken state, just like tasks have TASK_RUNNING.
 * It is considered woken when plist_node_empty(&q->list) || q->lock_ptr == 0.
 * The order of wakup is always to make the first condition true, then
 * wake up q->waiter, then make the second condition true.
 */
struct futex_q {
	struct plist_node list;
	/* There can only be a single waiter */
	wait_queue_head_t waiter;

	/* Which hash list lock to use: */
	spinlock_t *lock_ptr;

	/* Key which the futex is hashed on: */
	union futex_key key;

	/* Optional priority inheritance state: */
	struct futex_pi_state *pi_state;
	struct task_struct *task;

	/* Bitset for the optional bitmasked wakeup */
	u32 bitset;

#ifdef CONFIG_KRG_EPM
	pid_t waiter_pid;
	kerrighed_node_t hosting_node;
	struct list_head local_list;
#endif
};

/*
 * Hash buckets are shared by all the futex_keys that hash to the same
 * location.  Each key may have multiple futex_q structures, one for each task
 * waiting on a futex.
 */
struct futex_hash_bucket {
	spinlock_t lock;
	struct plist_head chain;
#ifdef CONFIG_KRG_EPM
	long id;
#endif
};

static struct futex_hash_bucket futex_queues[1<<FUTEX_HASHBITS];
#ifdef CONFIG_KRG_EPM
static struct list_head local_futex_queues;
spinlock_t local_futex_lock;
#endif

/*
 * We hash on the keys returned from get_futex_key (see below).
 */
#ifdef CONFIG_KRG_EPM
static u32 compute_futex_hash(union futex_key *key)
{
	u32 hash;

	if (key->both.krg_id)
		hash = jhash2((u32*)&key->both.word,
			      (sizeof(key->both.word)+sizeof(key->both.krg_id))/4,
			      key->both.offset);
	else
		hash = jhash2((u32*)&key->both.word,
			      (sizeof(key->both.word)+sizeof(key->both.ptr))/4,
			      key->both.offset);
	return hash;
}

static struct futex_hash_bucket *__vanilla_hash_futex(u32 hash)
{
	return &futex_queues[hash & ((1 << FUTEX_HASHBITS)-1)];
}

static struct futex_hash_bucket *vanilla_hash_futex(union futex_key *key)
#else
static struct futex_hash_bucket *hash_futex(union futex_key *key)
#endif
{
	u32 hash = jhash2((u32*)&key->both.word,
			  (sizeof(key->both.word)+sizeof(key->both.ptr))/4,
			  key->both.offset);
	return &futex_queues[hash & ((1 << FUTEX_HASHBITS)-1)];
}

#ifdef CONFIG_KRG_EPM
static struct futex_hash_bucket *krg_grab_futex(union futex_key *key)
{
	struct futex_hash_bucket *hb;
	u32 hash;

	BUG_ON(!key->both.krg_id);
	hash = compute_futex_hash(key);

	hb = _kddm_grab_object(futex_kddm_set, hash);
	if (!hb)
		hb = ERR_PTR(-ENOMEM);
	return hb;
}

static struct futex_hash_bucket *hash_futex(union futex_key *key)
{
	if (!key->both.krg_id)
		return vanilla_hash_futex(key);

	return krg_grab_futex(key);
}

static void krg_put_futex(struct futex_hash_bucket *hb)
{
	_kddm_put_object(futex_kddm_set, hb->id);
}
#endif

/*
 * Return 1 if two futex_keys are equal, 0 otherwise.
 */
static inline int match_futex(union futex_key *key1, union futex_key *key2)
{
#ifdef CONFIG_KRG_EPM
	if (key1->both.krg_id)
		return (key1->both.word == key2->both.word
			&& key1->both.krg_id == key2->both.krg_id
			&& key1->both.offset == key2->both.offset);
#endif
	return (key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}

/*
 * Take a reference to the resource addressed by a key.
 * Can be called while holding spinlocks.
 *
 */
static void get_futex_key_refs(union futex_key *key)
{
	if (!key->both.ptr)
		return;

	switch (key->both.offset & (FUT_OFF_INODE|FUT_OFF_MMSHARED)) {
	case FUT_OFF_INODE:
		atomic_inc(&key->shared.inode->i_count);
		break;
	case FUT_OFF_MMSHARED:
		atomic_inc(&key->private.mm->mm_count);
		break;
	}
}

/*
 * Drop a reference to the resource addressed by a key.
 * The hash bucket spinlock must not be held.
 */
static void drop_futex_key_refs(union futex_key *key)
{
	if (!key->both.ptr) {
#ifndef CONFIG_KRG_EPM
		/* If we're here then we tried to put a key we failed to get */
		WARN_ON_ONCE(1);
#endif
		return;
	}

	switch (key->both.offset & (FUT_OFF_INODE|FUT_OFF_MMSHARED)) {
	case FUT_OFF_INODE:
		iput(key->shared.inode);
		break;
	case FUT_OFF_MMSHARED:
		mmdrop(key->private.mm);
		break;
	}
}

/**
 * get_futex_key - Get parameters which are the keys for a futex.
 * @uaddr: virtual address of the futex
 * @fshared: 0 for a PROCESS_PRIVATE futex, 1 for PROCESS_SHARED
 * @key: address where result is stored.
 * @rw: mapping needs to be read/write (values: VERIFY_READ, VERIFY_WRITE)
 *
 * Returns a negative error code or 0
 * The key words are stored in *key on success.
 *
 * For shared mappings, it's (page->index, vma->vm_file->f_path.dentry->d_inode,
 * offset_within_page).  For private mappings, it's (uaddr, current->mm).
 * We can usually work out the index without swapping in the page.
 *
 * lock_page() might sleep, the caller should not hold a spinlock.
 */
static int
get_futex_key(u32 __user *uaddr, int fshared, union futex_key *key, int rw)
{
	unsigned long address = (unsigned long)uaddr;
	struct mm_struct *mm = current->mm;
	struct page *page;
	int err;

	/*
	 * The futex address must be "naturally" aligned.
	 */
	key->both.offset = address % PAGE_SIZE;
	if (unlikely((address % sizeof(u32)) != 0))
		return -EINVAL;
	address -= key->both.offset;

	/*
	 * PROCESS_PRIVATE futexes are fast.
	 * As the mm cannot disappear under us and the 'key' only needs
	 * virtual address, we dont even have to find the underlying vma.
	 * Note : We do have to check 'uaddr' is a valid user address,
	 *        but access_ok() should be faster than find_vma()
	 */
	if (!fshared) {
		if (unlikely(!access_ok(rw, uaddr, sizeof(u32))))
			return -EFAULT;
		key->private.mm = mm;
		key->private.address = address;
#ifdef CONFIG_KRG_EPM
		if (mm->mm_id)
			key->private.mm_id = mm->mm_id;
		else
			key->private.mm_id = 0;
#endif
		get_futex_key_refs(key);
		return 0;
	}

again:
	err = get_user_pages_fast(address, 1, rw == VERIFY_WRITE, &page);
	if (err < 0)
		return err;

	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		put_page(page);
		goto again;
	}

	/*
	 * Private mappings are handled in a simple way.
	 *
	 * NOTE: When userspace waits on a MAP_SHARED mapping, even if
	 * it's a read-only handle, it's expected that futexes attach to
	 * the object not the particular process.
	 */
	if (PageAnon(page)) {
		key->both.offset |= FUT_OFF_MMSHARED; /* ref taken on mm */
		key->private.mm = mm;
		key->private.address = address;
#ifdef CONFIG_KRG_EPM
		if (mm->mm_id)
			key->private.mm_id = mm->mm_id;
		else
			key->private.mm_id = 0;
#endif
	} else {
		key->both.offset |= FUT_OFF_INODE; /* inode-based key */
		key->shared.inode = page->mapping->host;
		key->shared.pgoff = page->index;
#ifdef CONFIG_KRG_EPM
		if (page->mapping->kddm_set)
			key->shared.mapping_id = page->mapping->kddm_set->id;
		else
			key->shared.mapping_id = 0;
#endif
	}

	get_futex_key_refs(key);

	unlock_page(page);
	put_page(page);
	return 0;
}

static inline
void put_futex_key(int fshared, union futex_key *key)
{
	drop_futex_key_refs(key);
}

#ifdef CONFIG_KRG_EPM
/*
 * local_futex_lock must be held by the caller
 */
static struct futex_q *find_local_futex_q(pid_t waiter_pid)
{
	struct list_head *tmp, *element;
	struct futex_q *this, *q = NULL;

	list_for_each_safe(element, tmp, &local_futex_queues) {
		this = list_entry(element, struct futex_q, local_list);
		if (this->waiter_pid == waiter_pid) {
			q = this;
			goto found;
		}
	}
found:
	return q;
}

static int futex_hb_alloc_object(struct kddm_obj *obj_entry,
				 struct kddm_set *kddm, objid_t objid)
{
	struct futex_hash_bucket *hb;
	hb = kmalloc(sizeof(*hb), GFP_KERNEL);
	if (!hb)
		return -ENOMEM;

	hb->id = objid;
	plist_head_init(&hb->chain, &hb->lock);
	spin_lock_init(&hb->lock);

	obj_entry->object = hb;
	return 0;
}

static int export_one_futex_q(struct rpc_desc *desc,
			      struct futex_q *q)
{
	int r;

	r = rpc_pack_type(desc, *q);

	return r;
}

static int futex_hb_export_object(struct rpc_desc *desc,
				  struct kddm_set *set,
				  struct kddm_obj *obj_entry,
				  objid_t objid,
				  int flags)
{
	long nb_futex_q;
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	struct plist_head *head;
	int r;

	hb = obj_entry->object;
	nb_futex_q = 0;
	head = &hb->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		nb_futex_q++;
	}

	r = rpc_pack_type(desc, nb_futex_q);
	if (r)
		goto err;

	plist_for_each_entry_safe(this, next, head, list) {
		r = export_one_futex_q(desc, this);
		if (r)
			goto err;
	}

err:
	return r;
}

static int import_one_futex_q(struct rpc_desc *desc,
			      struct futex_hash_bucket *hb)
{
	struct futex_q *q, *old_q;
	int r;

	q = kmalloc(sizeof(struct futex_q), GFP_KERNEL);
	if (!q) {
		r = -ENOMEM;
		goto err;
	}

	r = rpc_unpack_type(desc, *q);
	if (r)
		goto err;

	q->key.both.ptr = NULL;

	if (q->hosting_node != kerrighed_node_id) {
		q->pi_state = NULL;
		q->task = NULL;
	} else {
		/* futex queue is on local_queues */
		spin_lock(&local_futex_lock);
		old_q = find_local_futex_q(q->waiter_pid);
		BUG_ON(!old_q);

		if (!plist_node_empty(&old_q->list)) {
			/*
			 * process has been requeued remotely but is
			 * still queued to the wrong futex locally
			 */
			BUG_ON(match_futex(&q->key, &old_q->key));
			spin_lock(old_q->lock_ptr);
			plist_del(&old_q->list, &old_q->list.plist);
			spin_unlock(old_q->lock_ptr);
		}

		if (!match_futex(&q->key, &old_q->key)) {
			drop_futex_key_refs(&old_q->key);
			/*
			 * it would be better to take a local reference to
			 * the key but how ?
			 */
			old_q->key = q->key;
		}

		kfree(q);
		q = old_q;
		spin_unlock(&local_futex_lock);
	}
	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock);
	plist_head_init(&(q->list.plist), &hb->lock);
	BUG_ON(!plist_node_empty(&q->list));
	plist_add(&q->list, &hb->chain);
	spin_unlock(&hb->lock);
err:
	return r;
}

static void clean_local_futex_q_list(struct futex_hash_bucket *hb)
{
	struct plist_head *head;
	struct futex_q *this, *next;

	spin_lock(&hb->lock);
	head = &hb->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		plist_del(&this->list, &hb->chain);

		if (this->hosting_node != kerrighed_node_id)
			kfree(this);
	}

	BUG_ON(!plist_head_empty(&hb->chain));
	spin_unlock(&hb->lock);
}

static int futex_hb_import_object(struct rpc_desc *desc,
				  struct kddm_set *set,
				  struct kddm_obj *obj_entry,
				  objid_t objid,
				  int flags)
{
	long nb_futex_q, i;
	struct futex_hash_bucket *hb;
	int r;

	r = rpc_unpack_type(desc, nb_futex_q);
	if (r)
		goto err;

	hb = obj_entry->object;

	clean_local_futex_q_list(hb);

	for (i = 0; i < nb_futex_q ; i++) {
		r = import_one_futex_q(desc, hb);
		if (r)
			goto err;
	}

err:
	BUG_ON(r);
	return r;
}

static int futex_hb_remove_object(void *obj, struct kddm_set *kddm,
				  objid_t objid)
{
	struct futex_hash_bucket *hb = obj;
	BUG_ON(!plist_head_empty(&hb->chain));
	kfree(hb);
	return 0;
}

static struct iolinker_struct futex_io_linker = {
	.linker_name = "futex",
	.linker_id = FUTEX_LINKER,
	.alloc_object = futex_hb_alloc_object,
	.remove_object = futex_hb_remove_object,
	.import_object = futex_hb_import_object,
	.export_object = futex_hb_export_object,
};
#endif

static u32 cmpxchg_futex_value_locked(u32 __user *uaddr, u32 uval, u32 newval)
{
	u32 curval;

	pagefault_disable();
	curval = futex_atomic_cmpxchg_inatomic(uaddr, uval, newval);
	pagefault_enable();

	return curval;
}

static int get_futex_value_locked(u32 *dest, u32 __user *from)
{
	int ret;

	pagefault_disable();
	ret = __copy_from_user_inatomic(dest, from, sizeof(u32));
	pagefault_enable();

	return ret ? -EFAULT : 0;
}


/*
 * PI code:
 */
static int refill_pi_state_cache(void)
{
	struct futex_pi_state *pi_state;

	if (likely(current->pi_state_cache))
		return 0;

	pi_state = kzalloc(sizeof(*pi_state), GFP_KERNEL);

	if (!pi_state)
		return -ENOMEM;

	INIT_LIST_HEAD(&pi_state->list);
	/* pi_mutex gets initialized later */
	pi_state->owner = NULL;
	atomic_set(&pi_state->refcount, 1);
	pi_state->key = FUTEX_KEY_INIT;

	current->pi_state_cache = pi_state;

	return 0;
}

static struct futex_pi_state * alloc_pi_state(void)
{
	struct futex_pi_state *pi_state = current->pi_state_cache;

	WARN_ON(!pi_state);
	current->pi_state_cache = NULL;

	return pi_state;
}

static void free_pi_state(struct futex_pi_state *pi_state)
{
	if (!atomic_dec_and_test(&pi_state->refcount))
		return;

	/*
	 * If pi_state->owner is NULL, the owner is most probably dying
	 * and has cleaned up the pi_state already
	 */
	if (pi_state->owner) {
		spin_lock_irq(&pi_state->owner->pi_lock);
		list_del_init(&pi_state->list);
		spin_unlock_irq(&pi_state->owner->pi_lock);

		rt_mutex_proxy_unlock(&pi_state->pi_mutex, pi_state->owner);
	}

	if (current->pi_state_cache)
		kfree(pi_state);
	else {
		/*
		 * pi_state->list is already empty.
		 * clear pi_state->owner.
		 * refcount is at 0 - put it back to 1.
		 */
		pi_state->owner = NULL;
		atomic_set(&pi_state->refcount, 1);
		current->pi_state_cache = pi_state;
	}
}

/*
 * Look up the task based on what TID userspace gave us.
 * We dont trust it.
 */
static struct task_struct * futex_find_get_task(pid_t pid)
{
	struct task_struct *p;
	const struct cred *cred = current_cred(), *pcred;

	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (!p) {
		p = ERR_PTR(-ESRCH);
	} else {
		pcred = __task_cred(p);
		if (cred->euid != pcred->euid &&
		    cred->euid != pcred->uid)
			p = ERR_PTR(-ESRCH);
		else
			get_task_struct(p);
	}

	rcu_read_unlock();

	return p;
}

/*
 * This task is holding PI mutexes at exit time => bad.
 * Kernel cleans up PI-state, but userspace is likely hosed.
 * (Robust-futex cleanup is separate and might save the day for userspace.)
 */
void exit_pi_state_list(struct task_struct *curr)
{
	struct list_head *next, *head = &curr->pi_state_list;
	struct futex_pi_state *pi_state;
	struct futex_hash_bucket *hb;
	union futex_key key = FUTEX_KEY_INIT;

	if (!futex_cmpxchg_enabled)
		return;
	/*
	 * We are a ZOMBIE and nobody can enqueue itself on
	 * pi_state_list anymore, but we have to be careful
	 * versus waiters unqueueing themselves:
	 */
	spin_lock_irq(&curr->pi_lock);
	while (!list_empty(head)) {

		next = head->next;
		pi_state = list_entry(next, struct futex_pi_state, list);
		key = pi_state->key;

#ifdef CONFIG_KRG_EPM
		/*
		 * Calling kddm function is bad when holding spinlock.
		 * Anyway, I (mfertre) do not see any other solution here.
		 */
#endif
		hb = hash_futex(&key);
#ifdef CONFIG_KRG_EPM
		BUG_ON(IS_ERR(hb));
#endif
		spin_unlock_irq(&curr->pi_lock);

		spin_lock(&hb->lock);

		spin_lock_irq(&curr->pi_lock);
		/*
		 * We dropped the pi-lock, so re-check whether this
		 * task still owns the PI-state:
		 */
		if (head->next != next) {
			spin_unlock(&hb->lock);
#ifdef CONFIG_KRG_EPM
			if (key.both.krg_id)
				krg_put_futex(hb);
#endif
			continue;
		}

		WARN_ON(pi_state->owner != curr);
		WARN_ON(list_empty(&pi_state->list));
		list_del_init(&pi_state->list);
		pi_state->owner = NULL;
		spin_unlock_irq(&curr->pi_lock);

		rt_mutex_unlock(&pi_state->pi_mutex);

		spin_unlock(&hb->lock);
#ifdef CONFIG_KRG_EPM
		if (key.both.krg_id)
			krg_put_futex(hb);
#endif

		spin_lock_irq(&curr->pi_lock);
	}
	spin_unlock_irq(&curr->pi_lock);
}

static int
lookup_pi_state(u32 uval, struct futex_hash_bucket *hb,
		union futex_key *key, struct futex_pi_state **ps)
{
	struct futex_pi_state *pi_state = NULL;
	struct futex_q *this, *next;
	struct plist_head *head;
	struct task_struct *p;
	pid_t pid = uval & FUTEX_TID_MASK;

	head = &hb->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex(&this->key, key)) {
			/*
			 * Another waiter already exists - bump up
			 * the refcount and return its pi_state:
			 */
			pi_state = this->pi_state;
			/*
			 * Userspace might have messed up non PI and PI futexes
			 */
			if (unlikely(!pi_state))
				return -EINVAL;

			WARN_ON(!atomic_read(&pi_state->refcount));

			/*
			 * When pi_state->owner is NULL then the owner died
			 * and another waiter is on the fly. pi_state->owner
			 * is fixed up by the task which acquires
			 * pi_state->rt_mutex.
			 *
			 * We do not check for pid == 0 which can happen when
			 * the owner died and robust_list_exit() cleared the
			 * TID.
			 */
			if (pid && pi_state->owner) {
				/*
				 * Bail out if user space manipulated the
				 * futex value.
				 */
				if (pid != task_pid_vnr(pi_state->owner))
					return -EINVAL;
			}

			atomic_inc(&pi_state->refcount);
			*ps = pi_state;

			return 0;
		}
	}

	/*
	 * We are the first waiter - try to look up the real owner and attach
	 * the new pi_state to it, but bail out when TID = 0
	 */
	if (!pid)
		return -ESRCH;
	p = futex_find_get_task(pid);
	if (IS_ERR(p))
		return PTR_ERR(p);

	/*
	 * We need to look at the task state flags to figure out,
	 * whether the task is exiting. To protect against the do_exit
	 * change of the task flags, we do this protected by
	 * p->pi_lock:
	 */
	spin_lock_irq(&p->pi_lock);
	if (unlikely(p->flags & PF_EXITING)) {
		/*
		 * The task is on the way out. When PF_EXITPIDONE is
		 * set, we know that the task has finished the
		 * cleanup:
		 */
		int ret = (p->flags & PF_EXITPIDONE) ? -ESRCH : -EAGAIN;

		spin_unlock_irq(&p->pi_lock);
		put_task_struct(p);
		return ret;
	}

	pi_state = alloc_pi_state();

	/*
	 * Initialize the pi_mutex in locked state and make 'p'
	 * the owner of it:
	 */
	rt_mutex_init_proxy_locked(&pi_state->pi_mutex, p);

	/* Store the key for possible exit cleanups: */
	pi_state->key = *key;

	WARN_ON(!list_empty(&pi_state->list));
	list_add(&pi_state->list, &p->pi_state_list);
	pi_state->owner = p;
	spin_unlock_irq(&p->pi_lock);

	put_task_struct(p);

	*ps = pi_state;

	return 0;
}

#ifdef CONFIG_KRG_EPM
struct futex_wake_up_msg {
	union futex_key key;
	pid_t waiter_pid;
};

static void wake_futex(struct futex_q *q);

static int handle_krg_futex_wake_up(struct rpc_desc *desc, void *_msg,
				    size_t size)
{
	struct futex_wake_up_msg *msg = _msg;
	struct futex_hash_bucket *hb;
	struct plist_head *head;
	struct futex_q *this, *next;
	spinlock_t *lock_ptr;
	u32 hash;
	int ret = 0;

#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - futex %lx-%lx, pid waiting: %d\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       msg->key.both.word, msg->key.both.krg_id, msg->waiter_pid);
#endif

	hash = compute_futex_hash(&msg->key);

	/*
	 * using _kddm_find_object_raw is dangerous, we must ensure that the RPC
	 * call is done in a synchronous way while still grabbing the object.
	 */
	hb = _kddm_find_object_raw(futex_kddm_set, hash);
	if (!hb) {
		ret = -ENOMEM;
		goto requeued;
	}

	lock_ptr = &hb->lock;
	spin_lock(lock_ptr);

	head = &hb->chain;
	plist_for_each_entry_safe(this, next, head, list) {
		if (msg->waiter_pid == this->waiter_pid) {
			BUG_ON(this->hosting_node != kerrighed_node_id);

			/*
			 * No need to check the key: one process can wait on
			 * only one futex at the same time.
			 * Moreover, the key may be wrong if process has been
			 * remotely requeued but there is a hash collision
			 * and thus still linked to the same hash bucket.
			 */
			wake_futex(this);
			goto unlock;
		}
	}

	spin_unlock(lock_ptr);
	lock_ptr = NULL;

requeued:
	/*
	 * process has been requeued on another futex,
	 * check in local list
	 */
	spin_lock(&local_futex_lock);
	this = find_local_futex_q(msg->waiter_pid);
	BUG_ON(!this);
	/* process has been requeued, key can't be the right one */
	BUG_ON(match_futex(&msg->key, &this->key));

	lock_ptr = this->lock_ptr;
	spin_unlock(&local_futex_lock);

	spin_lock(lock_ptr);
	wake_futex(this);

unlock:
	if (lock_ptr)
		spin_unlock(lock_ptr);
	return ret;
}

static void krg_futex_wake_up(struct futex_q *q, spinlock_t *hb1_lock, spinlock_t *hb2_lock)
{
	int ret;
	struct futex_wake_up_msg msg;

#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - futex %lx-%lx, bitset: %u, pid waiting: %d\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       q->key.both.word, q->key.both.krg_id, q->bitset, q->waiter_pid);
#endif

	msg.key = q->key;
	msg.waiter_pid = q->waiter_pid;

	BUG_ON(!hb1_lock);
	BUG_ON(q->lock_ptr != hb1_lock && q->lock_ptr != hb2_lock);
	/*
	 * Unlock hb lock to please lockdep. Since we are still
	 * grabbing the kddm object, there is no consequence.
	 */
	if (hb2_lock)
		spin_unlock(hb2_lock);
	spin_unlock(hb1_lock);

	ret = rpc_sync(RPC_FUTEX_WAKE, q->hosting_node, &msg, sizeof(msg));

	spin_lock(hb1_lock);
	if (hb2_lock)
		spin_lock(hb2_lock);

	kfree(q);
}
#endif

/*
 * The hash bucket lock must be held when this is called.
 * Afterwards, the futex_q must not be accessed.
 */


#ifdef CONFIG_KRG_EPM
static void __wake_futex(struct futex_q *q,
			 spinlock_t *hb1_lock, spinlock_t *hb2_lock)
#else
static void wake_futex(struct futex_q *q)
#endif
{
#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - futex %lx-%lx, bitset: %u, pid waiting: %d\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       q->key.both.word, q->key.both.krg_id, q->bitset, q->waiter_pid);
#endif

#ifdef CONFIG_KRG_EPM
	if (!plist_node_empty(&q->list))
#endif
	plist_del(&q->list, &q->list.plist);

#ifdef CONFIG_KRG_EPM
	else
		/* it may happen if q has been requeued remotely */
		BUG_ON(q->hosting_node != KERRIGHED_NODE_ID_NONE
		       && q->hosting_node != kerrighed_node_id);

	if (q->hosting_node != KERRIGHED_NODE_ID_NONE
	    && q->hosting_node != kerrighed_node_id) {
		krg_futex_wake_up(q, hb1_lock, hb2_lock);
		return;
	}
#endif

	/*
	 * The lock in wake_up_all() is a crucial memory barrier after the
	 * plist_del() and also before assigning to q->lock_ptr.
	 */
	wake_up(&q->waiter);
	/*
	 * The waiting task can free the futex_q as soon as this is written,
	 * without taking any locks.  This must come last.
	 *
	 * A memory barrier is required here to prevent the following store to
	 * lock_ptr from getting ahead of the wakeup. Clearing the lock at the
	 * end of wake_up() does not prevent this store from moving.
	 */
	smp_wmb();
	q->lock_ptr = NULL;

	return;
}

#ifdef CONFIG_KRG_EPM
static void wake_futex(struct futex_q *q)
{
	__wake_futex(q, q->lock_ptr, NULL);
}
#endif

static int wake_futex_pi(u32 __user *uaddr, u32 uval, struct futex_q *this)
{
	struct task_struct *new_owner;
	struct futex_pi_state *pi_state = this->pi_state;
	u32 curval, newval;

	if (!pi_state)
		return -EINVAL;

	spin_lock(&pi_state->pi_mutex.wait_lock);
	new_owner = rt_mutex_next_owner(&pi_state->pi_mutex);

	/*
	 * This happens when we have stolen the lock and the original
	 * pending owner did not enqueue itself back on the rt_mutex.
	 * Thats not a tragedy. We know that way, that a lock waiter
	 * is on the fly. We make the futex_q waiter the pending owner.
	 */
	if (!new_owner)
		new_owner = this->task;

	/*
	 * We pass it to the next owner. (The WAITERS bit is always
	 * kept enabled while there is PI state around. We must also
	 * preserve the owner died bit.)
	 */
	if (!(uval & FUTEX_OWNER_DIED)) {
		int ret = 0;

		newval = FUTEX_WAITERS | task_pid_vnr(new_owner);

		curval = cmpxchg_futex_value_locked(uaddr, uval, newval);

		if (curval == -EFAULT)
			ret = -EFAULT;
		else if (curval != uval)
			ret = -EINVAL;
		if (ret) {
			spin_unlock(&pi_state->pi_mutex.wait_lock);
			return ret;
		}
	}

	spin_lock_irq(&pi_state->owner->pi_lock);
	WARN_ON(list_empty(&pi_state->list));
	list_del_init(&pi_state->list);
	spin_unlock_irq(&pi_state->owner->pi_lock);

	spin_lock_irq(&new_owner->pi_lock);
	WARN_ON(!list_empty(&pi_state->list));
	list_add(&pi_state->list, &new_owner->pi_state_list);
	pi_state->owner = new_owner;
	spin_unlock_irq(&new_owner->pi_lock);

	spin_unlock(&pi_state->pi_mutex.wait_lock);
	rt_mutex_unlock(&pi_state->pi_mutex);

	return 0;
}

static int unlock_futex_pi(u32 __user *uaddr, u32 uval)
{
	u32 oldval;

	/*
	 * There is no waiter, so we unlock the futex. The owner died
	 * bit has not to be preserved here. We are the owner:
	 */
	oldval = cmpxchg_futex_value_locked(uaddr, uval, 0);

	if (oldval == -EFAULT)
		return oldval;
	if (oldval != uval)
		return -EAGAIN;

	return 0;
}

/*
 * Express the locking dependencies for lockdep:
 */
static inline void
double_lock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
{
	if (hb1 <= hb2) {
		spin_lock(&hb1->lock);
		if (hb1 < hb2)
			spin_lock_nested(&hb2->lock, SINGLE_DEPTH_NESTING);
	} else { /* hb1 > hb2 */
		spin_lock(&hb2->lock);
		spin_lock_nested(&hb1->lock, SINGLE_DEPTH_NESTING);
	}
}

static inline void
#ifdef CONFIG_KRG_EPM
vanilla_double_unlock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
#else
double_unlock_hb(struct futex_hash_bucket *hb1, struct futex_hash_bucket *hb2)
#endif
{
	spin_unlock(&hb1->lock);
	if (hb1 != hb2)
		spin_unlock(&hb2->lock);
}

#ifdef CONFIG_KRG_EPM
static int krg_double_grab_futex(union futex_key *key1,
				 struct futex_hash_bucket **hb1,
				 union futex_key *key2,
				 struct futex_hash_bucket **hb2)
{
	u32 hash1, hash2;
	int ret = 0;

	hash1 = compute_futex_hash(key1);
	hash2 = compute_futex_hash(key2);

	if (hash1 < hash2) {
		if (!key1->both.krg_id)
			*hb1 = __vanilla_hash_futex(hash1);
		else {
			*hb1 = _kddm_grab_object(futex_kddm_set, hash1);
			if (!*hb1) {
				ret = -ENOMEM;
				goto out;
			}
		}

		if (!key2->both.krg_id)
			*hb2 = __vanilla_hash_futex(hash2);
		else {
			*hb2 = _kddm_grab_object(futex_kddm_set, hash2);
			if (!*hb2) {
				ret = -ENOMEM;
				goto err_put_hb1;
			}
		}

	} else if (hash1 > hash2) {

		if (!key2->both.krg_id)
			*hb2 = __vanilla_hash_futex(hash2);
		else {
			*hb2 = _kddm_grab_object(futex_kddm_set, hash2);
			if (!*hb2) {
				ret = -ENOMEM;
				goto out;
			}
		}

		if (!key1->both.krg_id)
			*hb1 = __vanilla_hash_futex(hash1);
		else {
			*hb1 = _kddm_grab_object(futex_kddm_set, hash1);
			if (!*hb1) {
				ret = -ENOMEM;
				goto err_put_hb2;
			}
		}

	} else { /* hash1 == hash2 */

		if (!key1->both.krg_id)
			*hb1 = __vanilla_hash_futex(hash1);
		else {
			*hb1 = _kddm_grab_object(futex_kddm_set, hash1);
			if (!*hb1) {
				ret = -ENOMEM;
				goto out;
			}
		}

		*hb2 = *hb1;
	}

	double_lock_hb(*hb1, *hb2);
	return ret;

out:
	return ret;
err_put_hb1:
	_kddm_put_object(futex_kddm_set, hash1);
	hb1 = NULL;
	goto out;
err_put_hb2:
	_kddm_put_object(futex_kddm_set, hash2);
	hb2 = NULL;
	goto out;
}

void double_unlock_hb(struct futex_hash_bucket *hb1,
		      struct futex_hash_bucket *hb2)
{
	vanilla_double_unlock_hb(hb1, hb2);

	if (hb1->id < hb2->id) {
		if (hb1->id)
			_kddm_put_object(futex_kddm_set, hb1->id);
		_kddm_put_object(futex_kddm_set, hb2->id);
	} else if (hb2->id < hb1->id) {
		if (hb2->id)
			_kddm_put_object(futex_kddm_set, hb2->id);
		_kddm_put_object(futex_kddm_set, hb1->id);
	} else { /* hb1->id == hb2-> id */
		if (hb1->id)
			_kddm_put_object(futex_kddm_set, hb1->id);
	}
}
#endif

/*
 * Wake up waiters matching bitset queued on this futex (uaddr).
 */
static int futex_wake(u32 __user *uaddr, int fshared, int nr_wake, u32 bitset)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	struct plist_head *head;
	union futex_key key = FUTEX_KEY_INIT;
	int ret;

	if (!bitset)
		return -EINVAL;

	ret = get_futex_key(uaddr, fshared, &key, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;

	hb = hash_futex(&key);
#ifdef CONFIG_KRG_EPM
	if (IS_ERR(hb)) {
		ret = PTR_ERR(hb);
		goto out_put_key;
	}
#endif
	spin_lock(&hb->lock);
	head = &hb->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex (&this->key, &key)) {
			if (this->pi_state) {
				ret = -EINVAL;
				break;
			}

			/* Check if one of the bits is set in both bitsets */
			if (!(this->bitset & bitset))
				continue;

			wake_futex(this);
			if (++ret >= nr_wake)
				break;
		}
	}

	spin_unlock(&hb->lock);
#ifdef CONFIG_KRG_EPM
	if (key.both.krg_id)
		krg_put_futex(hb);
out_put_key:
#endif
	put_futex_key(fshared, &key);
out:
	return ret;
}

/*
 * Wake up all waiters hashed on the physical page that is mapped
 * to this virtual address:
 */
static int
futex_wake_op(u32 __user *uaddr1, int fshared, u32 __user *uaddr2,
	      int nr_wake, int nr_wake2, int op)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	struct futex_hash_bucket *hb1, *hb2;
	struct plist_head *head;
	struct futex_q *this, *next;
	int ret, op_ret;

retry:
	ret = get_futex_key(uaddr1, fshared, &key1, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2, VERIFY_WRITE);
	if (unlikely(ret != 0))
		goto out_put_key1;

#ifdef CONFIG_KRG_EPM
retry_private:
	ret = krg_double_grab_futex(&key1, &hb1, &key2, &hb2);
	if (ret)
		goto out_put_keys;
#else
	hb1 = hash_futex(&key1);
	hb2 = hash_futex(&key2);

retry_private:
	double_lock_hb(hb1, hb2);
#endif
	op_ret = futex_atomic_op_inuser(op, uaddr2);
	if (unlikely(op_ret < 0)) {
		u32 dummy;

		double_unlock_hb(hb1, hb2);

#ifndef CONFIG_MMU
		/*
		 * we don't get EFAULT from MMU faults if we don't have an MMU,
		 * but we might get them from range checking
		 */
		ret = op_ret;
		goto out_put_keys;
#endif

		if (unlikely(op_ret != -EFAULT)) {
			ret = op_ret;
			goto out_put_keys;
		}

		ret = get_user(dummy, uaddr2);
		if (ret)
			goto out_put_keys;

		if (!fshared)
			goto retry_private;

		put_futex_key(fshared, &key2);
		put_futex_key(fshared, &key1);
		goto retry;
	}

	head = &hb1->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		if (match_futex (&this->key, &key1)) {
#ifdef CONFIG_KRG_EPM
			__wake_futex(this, &hb1->lock, &hb2->lock);
#else
			wake_futex(this);
#endif
			if (++ret >= nr_wake)
				break;
		}
	}

	if (op_ret > 0) {
		head = &hb2->chain;

		op_ret = 0;
		plist_for_each_entry_safe(this, next, head, list) {
			if (match_futex (&this->key, &key2)) {
#ifdef CONFIG_KRG_EPM
				__wake_futex(this, &hb1->lock, &hb2->lock);
#else
				wake_futex(this);
#endif
				if (++op_ret >= nr_wake2)
					break;
			}
		}
		ret += op_ret;
	}

	double_unlock_hb(hb1, hb2);
out_put_keys:
	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	return ret;
}

/*
 * Requeue all waiters hashed on one physical page to another
 * physical page.
 */
static int futex_requeue(u32 __user *uaddr1, int fshared, u32 __user *uaddr2,
			 int nr_wake, int nr_requeue, u32 *cmpval)
{
	union futex_key key1 = FUTEX_KEY_INIT, key2 = FUTEX_KEY_INIT;
	struct futex_hash_bucket *hb1, *hb2;
	struct plist_head *head1;
	struct futex_q *this, *next;
	int ret, drop_count = 0;

retry:
	ret = get_futex_key(uaddr1, fshared, &key1, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;
	ret = get_futex_key(uaddr2, fshared, &key2, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out_put_key1;

#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - futex1 %lx-%lx, futex2 %lx-%lx, nr_wake: %d, nr_requeue: %d\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       key1.both.word, key1.both.krg_id,
	       key2.both.word, key2.both.krg_id,
	       nr_wake, nr_requeue);
#endif

#ifdef CONFIG_KRG_EPM
retry_private:
	ret = krg_double_grab_futex(&key1, &hb1, &key2, &hb2);
	if (ret)
		goto out_put_keys;
#else
	hb1 = hash_futex(&key1);
	hb2 = hash_futex(&key2);

retry_private:
	double_lock_hb(hb1, hb2);
#endif
	if (likely(cmpval != NULL)) {
		u32 curval;

		ret = get_futex_value_locked(&curval, uaddr1);

		if (unlikely(ret)) {
			double_unlock_hb(hb1, hb2);

			ret = get_user(curval, uaddr1);
			if (ret)
				goto out_put_keys;

			if (!fshared)
				goto retry_private;

			put_futex_key(fshared, &key2);
			put_futex_key(fshared, &key1);
			goto retry;
		}
		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out_unlock;
		}
	}

	head1 = &hb1->chain;
	plist_for_each_entry_safe(this, next, head1, list) {
		if (!match_futex (&this->key, &key1))
			continue;
		if (++ret <= nr_wake) {
#ifdef CONFIG_KRG_EPM
			__wake_futex(this, &hb1->lock, &hb2->lock);
#else
			wake_futex(this);
#endif
		} else {
			/*
			 * If key1 and key2 hash to the same bucket, no need to
			 * requeue.
			 */
			if (likely(head1 != &hb2->chain)) {
				plist_del(&this->list, &hb1->chain);
				plist_add(&this->list, &hb2->chain);
				this->lock_ptr = &hb2->lock;
#ifdef CONFIG_DEBUG_PI_LIST
				this->list.plist.lock = &hb2->lock;
#endif
			}
#ifdef CONFIG_KRG_EPM
			/*
			 * there are several cases in which we have no reference
			 * on key1:
			 *  1) process is remote,
			 *  2) process is local but it has been remotely
			 *     requeued from a key X to key key1.
			 *
			 * check we are not in these cases.
			 */
			if (this->key.both.ptr)
				drop_count++;
#else
			drop_count++;
#endif

			this->key = key2;
			get_futex_key_refs(&key2);

			if (ret - nr_wake >= nr_requeue)
				break;
		}
	}

out_unlock:
	double_unlock_hb(hb1, hb2);

	/*
	 * drop_futex_key_refs() must be called outside the spinlocks. During
	 * the requeue we moved futex_q's from the hash bucket at key1 to the
	 * one at key2 and updated their key pointer.  We no longer need to
	 * hold the references to key1.
	 */
	while (--drop_count >= 0)
		drop_futex_key_refs(&key1);

out_put_keys:
	put_futex_key(fshared, &key2);
out_put_key1:
	put_futex_key(fshared, &key1);
out:
	return ret;
}

/* The key must be already stored in q->key. */
static inline struct futex_hash_bucket *queue_lock(struct futex_q *q)
{
	struct futex_hash_bucket *hb;

	init_waitqueue_head(&q->waiter);

	get_futex_key_refs(&q->key);
	hb = hash_futex(&q->key);
#ifdef CONFIG_KRG_EPM
	if (IS_ERR(hb)) {
		drop_futex_key_refs(&q->key);
		goto out;
	}
#endif
	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock);
#ifdef CONFIG_KRG_EPM
out:
#endif
	return hb;
}

static inline void queue_me(struct futex_q *q, struct futex_hash_bucket *hb)
{
	int prio;

	/*
	 * The priority used to register this element is
	 * - either the real thread-priority for the real-time threads
	 * (i.e. threads with a priority lower than MAX_RT_PRIO)
	 * - or MAX_RT_PRIO for non-RT threads.
	 * Thus, all RT-threads are woken first in priority order, and
	 * the others are woken last, in FIFO order.
	 */
	prio = min(current->normal_prio, MAX_RT_PRIO);

	plist_node_init(&q->list, prio);
#ifdef CONFIG_DEBUG_PI_LIST
	q->list.plist.lock = &hb->lock;
#endif
	plist_add(&q->list, &hb->chain);
	q->task = current;
#ifdef CONFIG_KRG_EPM
	INIT_LIST_HEAD(&q->local_list);
	if (q->key.both.krg_id) {
		q->waiter_pid = task_pid_knr(current);
		q->hosting_node = kerrighed_node_id;
	} else {
		q->waiter_pid = 0;
		q->hosting_node = KERRIGHED_NODE_ID_NONE;
	}
#endif
	spin_unlock(&hb->lock);

#ifdef CONFIG_KRG_EPM
	if (q->key.both.krg_id) {
		spin_lock(&local_futex_lock);
		list_add_tail(&q->local_list, &local_futex_queues);
		spin_unlock(&local_futex_lock);

		krg_put_futex(hb);
	}
#endif
}

static inline void
queue_unlock(struct futex_q *q, struct futex_hash_bucket *hb)
{
	spin_unlock(&hb->lock);
#ifdef CONFIG_KRG_EPM
	if (q->key.both.krg_id)
		krg_put_futex(hb);
#endif

	drop_futex_key_refs(&q->key);
}

/*
 * queue_me and unqueue_me must be called as a pair, each
 * exactly once.  They are called with the hashed spinlock held.
 */

/* Return 1 if we were still queued (ie. 0 means we were woken) */
static int unqueue_me(struct futex_q *q)
{
	spinlock_t *lock_ptr;
	int ret = 0;

	/* In the common case we don't take the spinlock, which is nice. */
retry:
	lock_ptr = q->lock_ptr;
	barrier();
	if (lock_ptr != NULL) {
#ifdef CONFIG_KRG_EPM
		struct futex_hash_bucket *hb;
		if (q->key.both.krg_id) {
			hb = krg_grab_futex(&q->key);
			BUG_ON(IS_ERR(hb));
		}
#endif
		spin_lock(lock_ptr);
		/*
		 * q->lock_ptr can change between reading it and
		 * spin_lock(), causing us to take the wrong lock.  This
		 * corrects the race condition.
		 *
		 * Reasoning goes like this: if we have the wrong lock,
		 * q->lock_ptr must have changed (maybe several times)
		 * between reading it and the spin_lock().  It can
		 * change again after the spin_lock() but only if it was
		 * already changed before the spin_lock().  It cannot,
		 * however, change back to the original value.  Therefore
		 * we can detect whether we acquired the correct lock.
		 */
		if (unlikely(lock_ptr != q->lock_ptr)) {
			spin_unlock(lock_ptr);
#ifdef CONFIG_KRG_EPM
			if (q->key.both.krg_id)
				krg_put_futex(hb);
#endif
			goto retry;
		}

#ifdef CONFIG_KRG_EPM
		if (plist_node_empty(&q->list))
			/* happens only for local futex_q requeued remotely */
			BUG_ON(q->hosting_node == KERRIGHED_NODE_ID_NONE);
		else
#else
		WARN_ON(plist_node_empty(&q->list));
#endif
		plist_del(&q->list, &q->list.plist);

		BUG_ON(q->pi_state);

		spin_unlock(lock_ptr);
#ifdef CONFIG_KRG_EPM
		if (q->key.both.krg_id)
			krg_put_futex(hb);
#endif
		ret = 1;
	}

#ifdef CONFIG_KRG_EPM
	if (q->hosting_node != KERRIGHED_NODE_ID_NONE) {
		BUG_ON(q->hosting_node != kerrighed_node_id);
		spin_lock(&local_futex_lock);
		list_del(&q->local_list);
		spin_unlock(&local_futex_lock);
	}
#endif

	drop_futex_key_refs(&q->key);
	return ret;
}

/*
 * PI futexes can not be requeued and must remove themself from the
 * hash bucket. The hash bucket lock (i.e. lock_ptr) is held on entry
 * and dropped here.
 */
static void unqueue_me_pi(struct futex_q *q)
{
	WARN_ON(plist_node_empty(&q->list));
	plist_del(&q->list, &q->list.plist);

	BUG_ON(!q->pi_state);
	free_pi_state(q->pi_state);
	q->pi_state = NULL;

	spin_unlock(q->lock_ptr);

	drop_futex_key_refs(&q->key);
}

/*
 * Fixup the pi_state owner with the new owner.
 *
 * Must be called with hash bucket lock held and mm->sem held for non
 * private futexes.
 */
static int fixup_pi_state_owner(u32 __user *uaddr, struct futex_q *q,
				struct task_struct *newowner, int fshared)
{
	u32 newtid = task_pid_vnr(newowner) | FUTEX_WAITERS;
	struct futex_pi_state *pi_state = q->pi_state;
	struct task_struct *oldowner = pi_state->owner;
	u32 uval, curval, newval;
	int ret;

	/* Owner died? */
	if (!pi_state->owner)
		newtid |= FUTEX_OWNER_DIED;

	/*
	 * We are here either because we stole the rtmutex from the
	 * pending owner or we are the pending owner which failed to
	 * get the rtmutex. We have to replace the pending owner TID
	 * in the user space variable. This must be atomic as we have
	 * to preserve the owner died bit here.
	 *
	 * Note: We write the user space value _before_ changing the pi_state
	 * because we can fault here. Imagine swapped out pages or a fork
	 * that marked all the anonymous memory readonly for cow.
	 *
	 * Modifying pi_state _before_ the user space value would
	 * leave the pi_state in an inconsistent state when we fault
	 * here, because we need to drop the hash bucket lock to
	 * handle the fault. This might be observed in the PID check
	 * in lookup_pi_state.
	 */
retry:
	if (get_futex_value_locked(&uval, uaddr))
		goto handle_fault;

	while (1) {
		newval = (uval & FUTEX_OWNER_DIED) | newtid;

		curval = cmpxchg_futex_value_locked(uaddr, uval, newval);

		if (curval == -EFAULT)
			goto handle_fault;
		if (curval == uval)
			break;
		uval = curval;
	}

	/*
	 * We fixed up user space. Now we need to fix the pi_state
	 * itself.
	 */
	if (pi_state->owner != NULL) {
		spin_lock_irq(&pi_state->owner->pi_lock);
		WARN_ON(list_empty(&pi_state->list));
		list_del_init(&pi_state->list);
		spin_unlock_irq(&pi_state->owner->pi_lock);
	}

	pi_state->owner = newowner;

	spin_lock_irq(&newowner->pi_lock);
	WARN_ON(!list_empty(&pi_state->list));
	list_add(&pi_state->list, &newowner->pi_state_list);
	spin_unlock_irq(&newowner->pi_lock);
	return 0;

	/*
	 * To handle the page fault we need to drop the hash bucket
	 * lock here. That gives the other task (either the pending
	 * owner itself or the task which stole the rtmutex) the
	 * chance to try the fixup of the pi_state. So once we are
	 * back from handling the fault we need to check the pi_state
	 * after reacquiring the hash bucket lock and before trying to
	 * do another fixup. When the fixup has been done already we
	 * simply return.
	 */
handle_fault:
	spin_unlock(q->lock_ptr);

	ret = get_user(uval, uaddr);

	spin_lock(q->lock_ptr);

	/*
	 * Check if someone else fixed it for us:
	 */
	if (pi_state->owner != oldowner)
		return 0;

	if (ret)
		return ret;

	goto retry;
}

/*
 * In case we must use restart_block to restart a futex_wait,
 * we encode in the 'flags' shared capability
 */
#define FLAGS_SHARED		0x01
#define FLAGS_CLOCKRT		0x02

static long futex_wait_restart(struct restart_block *restart);

static int futex_wait(u32 __user *uaddr, int fshared,
		      u32 val, ktime_t *abs_time, u32 bitset, int clockrt)
{
	struct task_struct *curr = current;
	struct restart_block *restart;
	DECLARE_WAITQUEUE(wait, curr);
	struct futex_hash_bucket *hb;
	struct futex_q q;
	union futex_key key;
	u32 uval;
	int ret;
	struct hrtimer_sleeper t;
	int rem = 0;

	if (!bitset)
		return -EINVAL;

	q.pi_state = NULL;
	q.bitset = bitset;
retry:
	q.key = FUTEX_KEY_INIT;
	ret = get_futex_key(uaddr, fshared, &q.key, VERIFY_READ);
	if (unlikely(ret != 0))
		goto out;

#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - futex %lx-%lx, bitset: %u\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       q.key.both.word, q.key.both.krg_id, q.bitset);
#endif

	/*
	 * The key must be saved in case it is overwritten by a requeue
	 */
	key = q.key;

retry_private:
	hb = queue_lock(&q);

#ifdef CONFIG_KRG_EPM
	if (IS_ERR(hb)) {
		ret = PTR_ERR(hb);
		goto out_put_key;
	}
#endif
	/*
	 * Access the page AFTER the hash-bucket is locked.
	 * Order is important:
	 *
	 *   Userspace waiter: val = var; if (cond(val)) futex_wait(&var, val);
	 *   Userspace waker:  if (cond(var)) { var = new; futex_wake(&var); }
	 *
	 * The basic logical guarantee of a futex is that it blocks ONLY
	 * if cond(var) is known to be true at the time of blocking, for
	 * any cond.  If we queued after testing *uaddr, that would open
	 * a race condition where we could block indefinitely with
	 * cond(var) false, which would violate the guarantee.
	 *
	 * A consequence is that futex_wait() can return zero and absorb
	 * a wakeup when *uaddr != val on entry to the syscall.  This is
	 * rare, but normal.
	 *
	 * For shared futexes, we hold the mmap semaphore, so the mapping
	 * cannot have changed since we looked it up in get_futex_key.
	 */
	ret = get_futex_value_locked(&uval, uaddr);

	if (unlikely(ret)) {
		queue_unlock(&q, hb);

		ret = get_user(uval, uaddr);
		if (ret)
			goto out_put_key;

		if (!fshared)
			goto retry_private;

		put_futex_key(fshared, &key);
		goto retry;
	}
	ret = -EWOULDBLOCK;
	if (unlikely(uval != val)) {
		queue_unlock(&q, hb);
		goto out_put_key;
	}

	/* Only actually queue if *uaddr contained val.  */
	queue_me(&q, hb);

	/*
	 * There might have been scheduling since the queue_me(), as we
	 * cannot hold a spinlock across the get_user() in case it
	 * faults, and we cannot just set TASK_INTERRUPTIBLE state when
	 * queueing ourselves into the futex hash.  This code thus has to
	 * rely on the futex_wake() code removing us from hash when it
	 * wakes us up.
	 */

	/* add_wait_queue is the barrier after __set_current_state. */
	__set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&q.waiter, &wait);
	/*
	 * !plist_node_empty() is safe here without any lock.
	 * q.lock_ptr != 0 is not safe, because of ordering against wakeup.
	 */
	if (likely(!plist_node_empty(&q.list))) {
		if (!abs_time)
			schedule();
		else {
			hrtimer_init_on_stack(&t.timer,
					      clockrt ? CLOCK_REALTIME :
					      CLOCK_MONOTONIC,
					      HRTIMER_MODE_ABS);
			hrtimer_init_sleeper(&t, current);
			hrtimer_set_expires_range_ns(&t.timer, *abs_time,
						     current->timer_slack_ns);

			hrtimer_start_expires(&t.timer, HRTIMER_MODE_ABS);
			if (!hrtimer_active(&t.timer))
				t.task = NULL;

			/*
			 * the timer could have already expired, in which
			 * case current would be flagged for rescheduling.
			 * Don't bother calling schedule.
			 */
			if (likely(t.task))
				schedule();

			hrtimer_cancel(&t.timer);

			/* Flag if a timeout occured */
			rem = (t.task == NULL);

			destroy_hrtimer_on_stack(&t.timer);
		}
	}
	__set_current_state(TASK_RUNNING);

	/*
	 * NOTE: we don't remove ourselves from the waitqueue because
	 * we are the only user of it.
	 */

	/* If we were woken (and unqueued), we succeeded, whatever. */
	ret = 0;
	if (!unqueue_me(&q))
		goto out_put_key;
	ret = -ETIMEDOUT;
	if (rem)
		goto out_put_key;

	/*
	 * We expect signal_pending(current), but another thread may
	 * have handled it for us already.
	 */
	ret = -ERESTARTSYS;
	if (!abs_time)
		goto out_put_key;

	restart = &current_thread_info()->restart_block;
	restart->fn = futex_wait_restart;
	restart->futex.uaddr = (u32 *)uaddr;
	restart->futex.val = val;
	restart->futex.time = abs_time->tv64;
	restart->futex.bitset = bitset;
	restart->futex.flags = 0;

	if (fshared)
		restart->futex.flags |= FLAGS_SHARED;
	if (clockrt)
		restart->futex.flags |= FLAGS_CLOCKRT;

	ret = -ERESTART_RESTARTBLOCK;

out_put_key:
	put_futex_key(fshared, &key);
out:
	return ret;
}


static long futex_wait_restart(struct restart_block *restart)
{
	u32 __user *uaddr = (u32 __user *)restart->futex.uaddr;
	int fshared = 0;
	ktime_t t;

	t.tv64 = restart->futex.time;
	restart->fn = do_no_restart_syscall;
	if (restart->futex.flags & FLAGS_SHARED)
		fshared = 1;
	return (long)futex_wait(uaddr, fshared, restart->futex.val, &t,
				restart->futex.bitset,
				restart->futex.flags & FLAGS_CLOCKRT);
}


/*
 * Userspace tried a 0 -> TID atomic transition of the futex value
 * and failed. The kernel side here does the whole locking operation:
 * if there are waiters then it will block, it does PI, etc. (Due to
 * races the kernel might see a 0 value of the futex too.)
 */
static int futex_lock_pi(u32 __user *uaddr, int fshared,
			 int detect, ktime_t *time, int trylock)
{
	struct hrtimer_sleeper timeout, *to = NULL;
	struct task_struct *curr = current;
	struct futex_hash_bucket *hb;
	u32 uval, newval, curval;
	struct futex_q q;
	int ret, lock_taken, ownerdied = 0;

	if (refill_pi_state_cache())
		return -ENOMEM;

	if (time) {
		to = &timeout;
		hrtimer_init_on_stack(&to->timer, CLOCK_REALTIME,
				      HRTIMER_MODE_ABS);
		hrtimer_init_sleeper(to, current);
		hrtimer_set_expires(&to->timer, *time);
	}

	q.pi_state = NULL;
retry:
	q.key = FUTEX_KEY_INIT;
	ret = get_futex_key(uaddr, fshared, &q.key, VERIFY_WRITE);
	if (unlikely(ret != 0))
		goto out;

retry_private:
	hb = queue_lock(&q);

retry_locked:
	ret = lock_taken = 0;

	/*
	 * To avoid races, we attempt to take the lock here again
	 * (by doing a 0 -> TID atomic cmpxchg), while holding all
	 * the locks. It will most likely not succeed.
	 */
	newval = task_pid_vnr(current);

	curval = cmpxchg_futex_value_locked(uaddr, 0, newval);

	if (unlikely(curval == -EFAULT))
		goto uaddr_faulted;

	/*
	 * Detect deadlocks. In case of REQUEUE_PI this is a valid
	 * situation and we return success to user space.
	 */
	if (unlikely((curval & FUTEX_TID_MASK) == task_pid_vnr(current))) {
		ret = -EDEADLK;
		goto out_unlock_put_key;
	}

	/*
	 * Surprise - we got the lock. Just return to userspace:
	 */
	if (unlikely(!curval))
		goto out_unlock_put_key;

	uval = curval;

	/*
	 * Set the WAITERS flag, so the owner will know it has someone
	 * to wake at next unlock
	 */
	newval = curval | FUTEX_WAITERS;

	/*
	 * There are two cases, where a futex might have no owner (the
	 * owner TID is 0): OWNER_DIED. We take over the futex in this
	 * case. We also do an unconditional take over, when the owner
	 * of the futex died.
	 *
	 * This is safe as we are protected by the hash bucket lock !
	 */
	if (unlikely(ownerdied || !(curval & FUTEX_TID_MASK))) {
		/* Keep the OWNER_DIED bit */
		newval = (curval & ~FUTEX_TID_MASK) | task_pid_vnr(current);
		ownerdied = 0;
		lock_taken = 1;
	}

	curval = cmpxchg_futex_value_locked(uaddr, uval, newval);

	if (unlikely(curval == -EFAULT))
		goto uaddr_faulted;
	if (unlikely(curval != uval))
		goto retry_locked;

	/*
	 * We took the lock due to owner died take over.
	 */
	if (unlikely(lock_taken))
		goto out_unlock_put_key;

	/*
	 * We dont have the lock. Look up the PI state (or create it if
	 * we are the first waiter):
	 */
	ret = lookup_pi_state(uval, hb, &q.key, &q.pi_state);

	if (unlikely(ret)) {
		switch (ret) {

		case -EAGAIN:
			/*
			 * Task is exiting and we just wait for the
			 * exit to complete.
			 */
			queue_unlock(&q, hb);
			put_futex_key(fshared, &q.key);
			cond_resched();
			goto retry;

		case -ESRCH:
			/*
			 * No owner found for this futex. Check if the
			 * OWNER_DIED bit is set to figure out whether
			 * this is a robust futex or not.
			 */
			if (get_futex_value_locked(&curval, uaddr))
				goto uaddr_faulted;

			/*
			 * We simply start over in case of a robust
			 * futex. The code above will take the futex
			 * and return happy.
			 */
			if (curval & FUTEX_OWNER_DIED) {
				ownerdied = 1;
				goto retry_locked;
			}
		default:
			goto out_unlock_put_key;
		}
	}

	/*
	 * Only actually queue now that the atomic ops are done:
	 */
	queue_me(&q, hb);

	WARN_ON(!q.pi_state);
	/*
	 * Block on the PI mutex:
	 */
	if (!trylock)
		ret = rt_mutex_timed_lock(&q.pi_state->pi_mutex, to, 1);
	else {
		ret = rt_mutex_trylock(&q.pi_state->pi_mutex);
		/* Fixup the trylock return value: */
		ret = ret ? 0 : -EWOULDBLOCK;
	}

	spin_lock(q.lock_ptr);

	if (!ret) {
		/*
		 * Got the lock. We might not be the anticipated owner
		 * if we did a lock-steal - fix up the PI-state in
		 * that case:
		 */
		if (q.pi_state->owner != curr)
			ret = fixup_pi_state_owner(uaddr, &q, curr, fshared);
	} else {
		/*
		 * Catch the rare case, where the lock was released
		 * when we were on the way back before we locked the
		 * hash bucket.
		 */
		if (q.pi_state->owner == curr) {
			/*
			 * Try to get the rt_mutex now. This might
			 * fail as some other task acquired the
			 * rt_mutex after we removed ourself from the
			 * rt_mutex waiters list.
			 */
			if (rt_mutex_trylock(&q.pi_state->pi_mutex))
				ret = 0;
			else {
				/*
				 * pi_state is incorrect, some other
				 * task did a lock steal and we
				 * returned due to timeout or signal
				 * without taking the rt_mutex. Too
				 * late. We can access the
				 * rt_mutex_owner without locking, as
				 * the other task is now blocked on
				 * the hash bucket lock. Fix the state
				 * up.
				 */
				struct task_struct *owner;
				int res;

				owner = rt_mutex_owner(&q.pi_state->pi_mutex);
				res = fixup_pi_state_owner(uaddr, &q, owner,
							   fshared);

				/* propagate -EFAULT, if the fixup failed */
				if (res)
					ret = res;
			}
		} else {
			/*
			 * Paranoia check. If we did not take the lock
			 * in the trylock above, then we should not be
			 * the owner of the rtmutex, neither the real
			 * nor the pending one:
			 */
			if (rt_mutex_owner(&q.pi_state->pi_mutex) == curr)
				printk(KERN_ERR "futex_lock_pi: ret = %d "
				       "pi-mutex: %p pi-state %p\n", ret,
				       q.pi_state->pi_mutex.owner,
				       q.pi_state->owner);
		}
	}

	/*
	 * If fixup_pi_state_owner() faulted and was unable to handle the
	 * fault, unlock it and return the fault to userspace.
	 */
	if (ret && (rt_mutex_owner(&q.pi_state->pi_mutex) == current))
		rt_mutex_unlock(&q.pi_state->pi_mutex);

	/* Unqueue and drop the lock */
	unqueue_me_pi(&q);

	if (to)
		destroy_hrtimer_on_stack(&to->timer);
	return ret != -EINTR ? ret : -ERESTARTNOINTR;

out_unlock_put_key:
	queue_unlock(&q, hb);

out_put_key:
	put_futex_key(fshared, &q.key);
out:
	if (to)
		destroy_hrtimer_on_stack(&to->timer);
	return ret;

uaddr_faulted:
	/*
	 * We have to r/w  *(int __user *)uaddr, and we have to modify it
	 * atomically.  Therefore, if we continue to fault after get_user()
	 * below, we need to handle the fault ourselves, while still holding
	 * the mmap_sem.  This can occur if the uaddr is under contention as
	 * we have to drop the mmap_sem in order to call get_user().
	 */
	queue_unlock(&q, hb);

	ret = get_user(uval, uaddr);
	if (ret)
		goto out_put_key;

	if (!fshared)
		goto retry_private;

	put_futex_key(fshared, &q.key);
	goto retry;
}


/*
 * Userspace attempted a TID -> 0 atomic transition, and failed.
 * This is the in-kernel slowpath: we look up the PI state (if any),
 * and do the rt-mutex unlock.
 */
static int futex_unlock_pi(u32 __user *uaddr, int fshared)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	u32 uval;
	struct plist_head *head;
	union futex_key key = FUTEX_KEY_INIT;
	int ret;

retry:
	if (get_user(uval, uaddr))
		return -EFAULT;
	/*
	 * We release only a lock we actually own:
	 */
	if ((uval & FUTEX_TID_MASK) != task_pid_vnr(current))
		return -EPERM;

	ret = get_futex_key(uaddr, fshared, &key, VERIFY_WRITE);
	if (unlikely(ret != 0))
		goto out;

	hb = hash_futex(&key);
#ifdef CONFIG_KRG_EPM
	if (IS_ERR(hb)) {
		ret = PTR_ERR(hb);
		goto out_put_key;
	}
#endif
	spin_lock(&hb->lock);

	/*
	 * To avoid races, try to do the TID -> 0 atomic transition
	 * again. If it succeeds then we can return without waking
	 * anyone else up:
	 */
	if (!(uval & FUTEX_OWNER_DIED))
		uval = cmpxchg_futex_value_locked(uaddr, task_pid_vnr(current), 0);


	if (unlikely(uval == -EFAULT))
		goto pi_faulted;
	/*
	 * Rare case: we managed to release the lock atomically,
	 * no need to wake anyone else up:
	 */
	if (unlikely(uval == task_pid_vnr(current)))
		goto out_unlock;

	/*
	 * Ok, other tasks may need to be woken up - check waiters
	 * and do the wakeup if necessary:
	 */
	head = &hb->chain;

	plist_for_each_entry_safe(this, next, head, list) {
		if (!match_futex (&this->key, &key))
			continue;
		ret = wake_futex_pi(uaddr, uval, this);
		/*
		 * The atomic access to the futex value
		 * generated a pagefault, so retry the
		 * user-access and the wakeup:
		 */
		if (ret == -EFAULT)
			goto pi_faulted;
		goto out_unlock;
	}
	/*
	 * No waiters - kernel unlocks the futex:
	 */
	if (!(uval & FUTEX_OWNER_DIED)) {
		ret = unlock_futex_pi(uaddr, uval);
		if (ret == -EFAULT)
			goto pi_faulted;
	}

out_unlock:
	spin_unlock(&hb->lock);
#ifdef CONFIG_KRG_EPM
	if (key.both.krg_id)
		krg_put_futex(hb);
out_put_key:
#endif
	put_futex_key(fshared, &key);

out:
	return ret;

pi_faulted:
	/*
	 * We have to r/w  *(int __user *)uaddr, and we have to modify it
	 * atomically.  Therefore, if we continue to fault after get_user()
	 * below, we need to handle the fault ourselves, while still holding
	 * the mmap_sem.  This can occur if the uaddr is under contention as
	 * we have to drop the mmap_sem in order to call get_user().
	 */
	spin_unlock(&hb->lock);
#ifdef CONFIG_KRG_EPM
	if (key.both.krg_id)
		krg_put_futex(hb);
#endif
	put_futex_key(fshared, &key);

	ret = get_user(uval, uaddr);
	if (!ret)
		goto retry;

	return ret;
}

/*
 * Support for robust futexes: the kernel cleans up held futexes at
 * thread exit time.
 *
 * Implementation: user-space maintains a per-thread list of locks it
 * is holding. Upon do_exit(), the kernel carefully walks this list,
 * and marks all locks that are owned by this thread with the
 * FUTEX_OWNER_DIED bit, and wakes up a waiter (if any). The list is
 * always manipulated with the lock held, so the list is private and
 * per-thread. Userspace also maintains a per-thread 'list_op_pending'
 * field, to allow the kernel to clean up if the thread dies after
 * acquiring the lock, but just before it could have added itself to
 * the list. There can only be one such pending lock.
 */

/**
 * sys_set_robust_list - set the robust-futex list head of a task
 * @head: pointer to the list-head
 * @len: length of the list-head, as userspace expects
 */
SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head,
		size_t, len)
{
	if (!futex_cmpxchg_enabled)
		return -ENOSYS;
	/*
	 * The kernel knows only one size for now:
	 */
	if (unlikely(len != sizeof(*head)))
		return -EINVAL;

	current->robust_list = head;

	return 0;
}

/**
 * sys_get_robust_list - get the robust-futex list head of a task
 * @pid: pid of the process [zero for current task]
 * @head_ptr: pointer to a list-head pointer, the kernel fills it in
 * @len_ptr: pointer to a length field, the kernel fills in the header size
 */
SYSCALL_DEFINE3(get_robust_list, int, pid,
		struct robust_list_head __user * __user *, head_ptr,
		size_t __user *, len_ptr)
{
	struct robust_list_head __user *head;
	unsigned long ret;
	const struct cred *cred = current_cred(), *pcred;

	if (!futex_cmpxchg_enabled)
		return -ENOSYS;

	if (!pid)
		head = current->robust_list;
	else {
		struct task_struct *p;

		ret = -ESRCH;
		rcu_read_lock();
		p = find_task_by_vpid(pid);
		if (!p)
			goto err_unlock;
		ret = -EPERM;
		pcred = __task_cred(p);
		if (cred->euid != pcred->euid &&
		    cred->euid != pcred->uid &&
		    !capable(CAP_SYS_PTRACE))
			goto err_unlock;
		head = p->robust_list;
		rcu_read_unlock();
	}

	if (put_user(sizeof(*head), len_ptr))
		return -EFAULT;
	return put_user(head, head_ptr);

err_unlock:
	rcu_read_unlock();

	return ret;
}

/*
 * Process a futex-list entry, check whether it's owned by the
 * dying task, and do notification if so:
 */
int handle_futex_death(u32 __user *uaddr, struct task_struct *curr, int pi)
{
	u32 uval, nval, mval;

retry:
	if (get_user(uval, uaddr))
		return -1;

	if ((uval & FUTEX_TID_MASK) == task_pid_vnr(curr)) {
		/*
		 * Ok, this dying thread is truly holding a futex
		 * of interest. Set the OWNER_DIED bit atomically
		 * via cmpxchg, and if the value had FUTEX_WAITERS
		 * set, wake up a waiter (if any). (We have to do a
		 * futex_wake() even if OWNER_DIED is already set -
		 * to handle the rare but possible case of recursive
		 * thread-death.) The rest of the cleanup is done in
		 * userspace.
		 */
		mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
		nval = futex_atomic_cmpxchg_inatomic(uaddr, uval, mval);

		if (nval == -EFAULT)
			return -1;

		if (nval != uval)
			goto retry;

		/*
		 * Wake robust non-PI futexes here. The wakeup of
		 * PI futexes happens in exit_pi_state():
		 */
		if (!pi && (uval & FUTEX_WAITERS))
			futex_wake(uaddr, 1, 1, FUTEX_BITSET_MATCH_ANY);
	}
	return 0;
}

/*
 * Fetch a robust-list pointer. Bit 0 signals PI futexes:
 */
static inline int fetch_robust_entry(struct robust_list __user **entry,
				     struct robust_list __user * __user *head,
				     int *pi)
{
	unsigned long uentry;

	if (get_user(uentry, (unsigned long __user *)head))
		return -EFAULT;

	*entry = (void __user *)(uentry & ~1UL);
	*pi = uentry & 1;

	return 0;
}

/*
 * Walk curr->robust_list (very carefully, it's a userspace list!)
 * and mark any locks found there dead, and notify any waiters.
 *
 * We silently return on any sign of list-walking problem.
 */
void exit_robust_list(struct task_struct *curr)
{
	struct robust_list_head __user *head = curr->robust_list;
	struct robust_list __user *entry, *next_entry, *pending;
	unsigned int limit = ROBUST_LIST_LIMIT, pi, next_pi, pip;
	unsigned long futex_offset;
	int rc;

	if (!futex_cmpxchg_enabled)
		return;

	/*
	 * Fetch the list head (which was registered earlier, via
	 * sys_set_robust_list()):
	 */
	if (fetch_robust_entry(&entry, &head->list.next, &pi))
		return;
	/*
	 * Fetch the relative futex offset:
	 */
	if (get_user(futex_offset, &head->futex_offset))
		return;
	/*
	 * Fetch any possibly pending lock-add first, and handle it
	 * if it exists:
	 */
	if (fetch_robust_entry(&pending, &head->list_op_pending, &pip))
		return;

	next_entry = NULL;	/* avoid warning with gcc */
	while (entry != &head->list) {
		/*
		 * Fetch the next entry in the list before calling
		 * handle_futex_death:
		 */
		rc = fetch_robust_entry(&next_entry, &entry->next, &next_pi);
		/*
		 * A pending lock might already be on the list, so
		 * don't process it twice:
		 */
		if (entry != pending)
			if (handle_futex_death((void __user *)entry + futex_offset,
						curr, pi))
				return;
		if (rc)
			return;
		entry = next_entry;
		pi = next_pi;
		/*
		 * Avoid excessively long or circular lists:
		 */
		if (!--limit)
			break;

		cond_resched();
	}

	if (pending)
		handle_futex_death((void __user *)pending + futex_offset,
				   curr, pip);
}

long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3)
{
	int clockrt, ret = -ENOSYS;
	int cmd = op & FUTEX_CMD_MASK;
	int fshared = 0;

	if (!(op & FUTEX_PRIVATE_FLAG))
		fshared = 1;

	clockrt = op & FUTEX_CLOCK_REALTIME;
	if (clockrt && cmd != FUTEX_WAIT_BITSET)
		return -ENOSYS;

#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - cmd: %d, uaddr: %p, uaddr2: %p, val: %u, val2: %u, val3: %u\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       cmd, uaddr, uaddr2, val, val2, val3);
#endif

	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAIT_BITSET:
		ret = futex_wait(uaddr, fshared, val, timeout, val3, clockrt);
		break;
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
	case FUTEX_WAKE_BITSET:
		ret = futex_wake(uaddr, fshared, val, val3);
		break;
	case FUTEX_REQUEUE:
		ret = futex_requeue(uaddr, fshared, uaddr2, val, val2, NULL);
		break;
	case FUTEX_CMP_REQUEUE:
		ret = futex_requeue(uaddr, fshared, uaddr2, val, val2, &val3);
		break;
	case FUTEX_WAKE_OP:
		ret = futex_wake_op(uaddr, fshared, uaddr2, val, val2, val3);
		break;
	case FUTEX_LOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_lock_pi(uaddr, fshared, val, timeout, 0);
		break;
	case FUTEX_UNLOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_unlock_pi(uaddr, fshared);
		break;
	case FUTEX_TRYLOCK_PI:
		if (futex_cmpxchg_enabled)
			ret = futex_lock_pi(uaddr, fshared, 0, timeout, 1);
		break;
	default:
		ret = -ENOSYS;
	}

#ifdef CONFIG_KRG_DEBUG
	printk("(%s-%d) %s - cmd: %d, uaddr: %p, uaddr2: %p, val: %u, val2: %u, val3: %u"
	       "- ret = %d\n",
	       current->comm, task_pid_knr(current), __PRETTY_FUNCTION__,
	       cmd, uaddr, uaddr2, val, val2, val3, ret);
#endif
	return ret;
}


SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
		struct timespec __user *, utime, u32 __user *, uaddr2,
		u32, val3)
{
	struct timespec ts;
	ktime_t t, *tp = NULL;
	u32 val2 = 0;
	int cmd = op & FUTEX_CMD_MASK;

	if (utime && (cmd == FUTEX_WAIT || cmd == FUTEX_LOCK_PI ||
		      cmd == FUTEX_WAIT_BITSET)) {
		if (copy_from_user(&ts, utime, sizeof(ts)) != 0)
			return -EFAULT;
		if (!timespec_valid(&ts))
			return -EINVAL;

		t = timespec_to_ktime(ts);
		if (cmd == FUTEX_WAIT)
			t = ktime_add_safe(ktime_get(), t);
		tp = &t;
	}
	/*
	 * requeue parameter in 'utime' if cmd == FUTEX_REQUEUE.
	 * number of waiters to wake in 'utime' if cmd == FUTEX_WAKE_OP.
	 */
	if (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE ||
	    cmd == FUTEX_WAKE_OP)
		val2 = (u32) (unsigned long) utime;

	return do_futex(uaddr, op, val, tp, uaddr2, val2, val3);
}

#ifdef CONFIG_KRG_EPM
int futex_krgsyms_register(void)
{
	return krgsyms_register(KRGSYMS_FUTEX_WAIT_RESTART, futex_wait_restart);
}

int futex_krgsyms_unregister(void)
{
	return krgsyms_unregister(KRGSYMS_FUTEX_WAIT_RESTART);
}
#endif

static int __init futex_init(void)
{
	u32 curval;
	int i;

	/*
	 * This will fail and we want it. Some arch implementations do
	 * runtime detection of the futex_atomic_cmpxchg_inatomic()
	 * functionality. We want to know that before we call in any
	 * of the complex code paths. Also we want to prevent
	 * registration of robust lists in that case. NULL is
	 * guaranteed to fault and we get -EFAULT on functional
	 * implementation, the non functional ones will return
	 * -ENOSYS.
	 */
	curval = cmpxchg_futex_value_locked(NULL, 0, 0);
	if (curval == -EFAULT)
		futex_cmpxchg_enabled = 1;

	for (i = 0; i < ARRAY_SIZE(futex_queues); i++) {
		plist_head_init(&futex_queues[i].chain, &futex_queues[i].lock);
		spin_lock_init(&futex_queues[i].lock);
	}

	return 0;
}
__initcall(futex_init);

#ifdef CONFIG_KRG_EPM
int krg_futex_init(void)
{
	int ret = 0;

	register_io_linker(FUTEX_LINKER, &futex_io_linker);

	futex_kddm_set = create_new_kddm_set(kddm_def_ns, FUTEX_KDDM_ID,
					     FUTEX_LINKER, KDDM_RR_DEF_OWNER,
					     0, 0);
	if (IS_ERR(futex_kddm_set))
		BUG();

	rpc_register_int(RPC_FUTEX_WAKE, handle_krg_futex_wake_up, 0);

	INIT_LIST_HEAD(&local_futex_queues);
	spin_lock_init(&local_futex_lock);

	return ret;
}
#endif
