/*
 *  lib/global_lock.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *  Copyright (C) 2007 Marko Novak - Xlab
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <kddm/kddm.h>
#include <asm/system.h>

static struct kddm_set *lock_set;

#define ZERO_SIZE_LOCK_OBJECT	((void *) 0xe5e5e5e5)

/* Avoid using memory for 0-sized objects */
static int global_lock_alloc_object(struct kddm_obj *obj_entry,
				    struct kddm_set *set,
				    objid_t objid)
{
	obj_entry->object = ZERO_SIZE_LOCK_OBJECT;
	return 0;
}

/* Avoid a useless rpc_pack() ... */
static int global_lock_export_object(struct rpc_desc *desc,
				     struct kddm_set *set,
				     struct kddm_obj *obj_entry,
				     objid_t objid,
				     int flags)
{
	return 0;
}

/* ... and its useless rpc_unpack() counterpart */
static int global_lock_import_object(struct rpc_desc *desc,
				     struct kddm_set *set,
				     struct kddm_obj *obj_entry,
				     objid_t objid,
				     int flags)
{
	return 0;
}

/* Do not try kfree(ZERO_SIZE_LOCK_OBJECT) */
static int global_lock_remove_object(void *object,
				     struct kddm_set *set,
				     objid_t objid)
{
	return 0;
}

static struct iolinker_struct global_lock_io_linker = {
	.linker_name   = "global lock",
	.linker_id     = GLOBAL_LOCK_LINKER,
	.alloc_object  = global_lock_alloc_object,
	.export_object = global_lock_export_object,
	.import_object = global_lock_import_object,
	.remove_object = global_lock_remove_object
};

int global_lock_try_writelock(unsigned long lock_id)
{
	void *ret = _kddm_try_grab_object(lock_set, lock_id);
	int retval;

	if (likely(ret == ZERO_SIZE_LOCK_OBJECT))
		retval = 0;
	else if (likely(ret == ERR_PTR(-EBUSY)))
		retval = -EAGAIN;
	else if (!ret)
		retval = -ENOMEM;
	else
		retval = PTR_ERR(ret);

	return retval;
}

int global_lock_writelock(unsigned long lock_id)
{
	void *ret = _kddm_grab_object(lock_set, lock_id);
	int retval;

	if (likely(ret == ZERO_SIZE_LOCK_OBJECT))
		retval = 0;
	else if (!ret)
		retval = -ENOMEM;
	else
		retval = PTR_ERR(ret);

	return retval;
}

int global_lock_readlock(unsigned long lock_id)
{
	void *ret = _kddm_get_object(lock_set, lock_id);
	int retval;

	if (likely(ret == ZERO_SIZE_LOCK_OBJECT))
		retval = 0;
	else if (!ret)
		retval = -ENOMEM;
	else
		retval = PTR_ERR(ret);

	return retval;
}

void global_lock_unlock(unsigned long lock_id)
{
	_kddm_put_object(lock_set, lock_id);
}

int init_global_lock(void)
{
	register_io_linker(GLOBAL_LOCK_LINKER, &global_lock_io_linker);

	lock_set = create_new_kddm_set(kddm_def_ns, GLOBAL_LOCK_KDDM_SET_ID,
				       GLOBAL_LOCK_LINKER,
				       KDDM_RR_DEF_OWNER,
				       0, KDDM_LOCAL_EXCLUSIVE);
	BUG_ON(!lock_set);
	if (IS_ERR(lock_set))
		return PTR_ERR(lock_set);

	return 0;
}

void cleanup_global_lock(void)
{
}
