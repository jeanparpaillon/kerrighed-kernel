/*
 *  kerrighed/scheduler/global_config.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *  Copyright (C) 2007 Marko Novak - Xlab
 */

/*
 * Helper functions to make configfs operations on kerrighed's schedulers global
 *
 * The principle is to replicate the operations done at user-level (mkdir,
 * rmdir, symlink, unlink, and write), and to infer from the context if the
 * operation is directly done by user-level, or by the replication engine. The
 * current criterion is whether current is a kernel thread (assuming an RPC
 * handler) or not.
 *
 * To ensure that all operations on a given item are done in the same order on
 * all nodes, they are globally serialized.  However, since many configfs
 * callbacks are called with mutex held on directories, we cannot be sure that
 * two concurrent global operations on a same item will not deadlock. For this
 * reason we use a global lock that implements only try_lock and unlock
 * operations. If try_lock fails, the operation fails and the user is requested
 * to try again. The above deadlock should be avoidable with a more globalized
 * vfs.
 */

#include <linux/configfs.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/gfp.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <kerrighed/krginit.h>
#include <kerrighed/sys/types.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/workqueue.h>
#ifdef CONFIG_KRG_EPM
#include <kerrighed/ghost.h>
#endif
#include <kerrighed/scheduler/global_config.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>
#include <kddm/kddm.h>

#include <asm/fcntl.h>
#include <asm/system.h>

#include "internal.h"
#include "hashed_string_list.h"
#include "string_list.h"
#include "global_lock.h"

static struct kddm_set *global_items_set;

static struct vfsmount *scheduler_fs_mount; /* vfsmount attached to configfs */
static int mount_count;

int global_config_freeze(void)
{
	return global_lock_readlock(0);
}

void global_config_thaw(void)
{
	global_lock_unlock(0);
}

static inline int in_krg_scheduler_subsys(struct config_item *item)
{
	return item && item != &krg_scheduler_subsys.su_group.cg_item;
}

/* Two following functions adapted from configfs/symlink.c */

static int item_path_length(struct config_item *item)
{
	struct config_item *p = item;
	int length = 1;
	do {
		length += strlen(config_item_name(p)) + 1;
		p = p->ci_parent;
	} while (in_krg_scheduler_subsys(p));
	return length;
}

static void fill_item_path(struct config_item *item, char *buffer, int length)
{
	struct config_item *p;

	--length;
	for (p = item; in_krg_scheduler_subsys(p); p = p->ci_parent) {
		int cur = strlen(config_item_name(p));

		/* back up enough to print this bus id with '/' */
		length -= cur;
		strncpy(buffer + length, config_item_name(p), cur);
		*(buffer + --length) = '/';
	}
}

/**
 * Returns the absolute path combining parent and name, assuming that root is at
 * the configfs scheduler subsystem entry.
 *
 * @param parent       base config_item
 * @param name         component to catenate to parent's path
 *
 * @return	       pointer to a newly allocated string containing the
 *                     absolute path. The path must be freed with put_path.
 */
static char *get_full_path(struct config_item *parent, const char *name)
{
	size_t parent_len = item_path_length(parent);
	size_t full_len = parent_len - 1;
	char *path;

	if (name)
		full_len += 1 + strlen(name);
	path = kmalloc(full_len + 1, GFP_KERNEL);
	if (!path)
		return NULL;
	fill_item_path(parent, path, parent_len);
	if (name) {
		path[parent_len - 1] = '/';
		strcpy(path + parent_len, name);
	} else
		path[parent_len - 1] = '\0';
	return path;
}

static void put_path(char *path)
{
	kfree(path);
}

/**
 * Prepares a directory operation by taking the mutex on the parent inode of
 * an entry and returning a dentry for the entry.
 *
 * @param child_name   path to the entry, assumed absolute from configfs
 *		       scheduler subsystem entry.
 *
 * @return	       a valid dentry to the target entry, or error. The valid
 *		       dentry must be released with put_child_dentry.
 */
static struct dentry *get_child_dentry(const char *child_name)
{
	struct dentry *d_dir;
	struct dentry *d_child;
	const char *last_child_comp;
	const char *real_child_name = child_name;
	int err;

	d_dir = dget(krg_scheduler_subsys.su_group.cg_item.ci_dentry);

	last_child_comp = strrchr(child_name, '/');
	if (last_child_comp) {
		struct nameidata nd;

		err = vfs_path_lookup(d_dir, scheduler_fs_mount,
				      child_name, LOOKUP_PARENT, &nd);

		dput(d_dir);

		if (err)
			return ERR_PTR(err);

		d_dir = dget(nd.path.dentry);
		path_put(&nd.path);
		BUG_ON(!last_child_comp[1]);
		real_child_name = last_child_comp + 1;
	}

	mutex_lock_nested(&d_dir->d_inode->i_mutex, I_MUTEX_PARENT);
	d_child = lookup_one_len(real_child_name, d_dir, strlen(real_child_name));
	if (IS_ERR(d_child))
		mutex_unlock(&d_dir->d_inode->i_mutex);
	dput(d_dir);
	return d_child;
}

static void put_child_dentry(struct dentry *d_child)
{
	struct dentry *d_dir;

	d_dir = dget(d_child->d_parent);
	dput(d_child);
	mutex_unlock(&d_dir->d_inode->i_mutex);
	dput(d_dir);
}

/**
 * Change current's root to configfs scheduler subsystem'root, and save
 * previous root in parameters.
 *
 * @param prev_root    valid pointer to a struct path
 *
 * @return	       prev_rootmnt and prev_root are filled with the previous
 *		       root. They must be restored with chroot_restore, or
 *		       mntput/dput when not needed anymore.
 */
static void chroot_to_scheduler_subsystem(struct path *prev_root)
{
	struct path new_root;

	/*
	 * These two values won't change unless a pivot_root is running ...
	 * but we assume that this can not happen.
	 * Locking is more used for memory barriers than for anything else.
	 */
	read_lock(&current->fs->lock);
	*prev_root = current->fs->root;
	path_get(prev_root);
	read_unlock(&current->fs->lock);

	new_root.mnt = scheduler_fs_mount;
	new_root.dentry = krg_scheduler_subsys.su_group.cg_item.ci_dentry;
	set_fs_root(current->fs, &new_root);
}

static void chroot_restore(struct path *prev_root)
{
	set_fs_root(current->fs, prev_root);
	path_put(prev_root);
}

/* Low level handling of global config operations */

enum config_op {
	CO_MKDIR,
	CO_RMDIR,
	CO_SYMLINK,
	CO_UNLINK,
	CO_WRITE,
};

static enum config_op reverse_op(enum config_op op)
{
	switch (op) {
	case CO_MKDIR:
		return CO_RMDIR;
	case CO_SYMLINK:
		return CO_UNLINK;
	default:
		BUG();
	}
}

struct config_op_message {
	enum config_op op;
};


/**
 * Prepare to broadcast a global config operation to all *other* nodes.
 *
 * @param op	       op code of the operation
 * @param nodes	       valid pointer to a nodes set
 *
 * @return	       a valid rpc_desc to do operation-specific communications,
 *		       or error. nodes is filled with the nodes contacted for
 *		       the operation.
 */
static struct rpc_desc *global_config_op_begin(enum config_op op,
					       krgnodemask_t *nodes)
{
	struct config_op_message msg = {
		.op = op
	};
	struct rpc_desc *desc;
	krgnodemask_t _nodes = krgnode_online_map;
	int err;

	krgnode_clear(kerrighed_node_id, _nodes);
	desc = rpc_begin_m(GLOBAL_CONFIG_OP, &_nodes);
	if (!desc)
		return ERR_PTR(-ENOMEM);

	err = rpc_pack_type(desc, msg);
	if (err) {
		rpc_cancel(desc);
		rpc_end(desc, 0);
		return ERR_PTR(err);
	} else {
		*nodes = _nodes;
		return desc;
	}
}

/**
 * Close a global config operation by retrieving the result from all contacted
 * nodes.
 *
 * @param desc	       rpc_desc as returned by global_config_op_begin.
 *		       Will be closed before returning a result.
 * @param nodes	       valid pointer to a nodes set, previously filled by
 *		       global_config_op_begin
 *
 * @return	       0 if the operation succeeded on all contacted nodes, or
 *                     error
 */
static int global_config_op_end(struct rpc_desc *desc, krgnodemask_t *nodes)
{
	int res = 0;
	kerrighed_node_t node;
	int err;

	for_each_krgnode_mask(node, *nodes) {
		err = rpc_unpack_type_from(desc, node, res);
		if (!err && res) {
			rpc_cancel(desc);
			goto out;
		}
	}

out:
	rpc_end(desc, 0);

	return res;
}

static void handle_global_config_write(struct rpc_desc *desc,
				       void *_msg, size_t size);
static void handle_global_config_dir_op(struct rpc_desc *desc,
					void *_msg, size_t size);

/**
 * Generic RPC handler for global config operations
 */
static void handle_global_config_op(struct rpc_desc *desc,
				    void *_msg, size_t size)
{
	struct config_op_message *msg = _msg;

	if (msg->op == CO_WRITE)
		handle_global_config_write(desc, _msg, size);
	else
		handle_global_config_dir_op(desc, _msg, size);
}

/**
 * Helper function to send a string
 *
 * @param desc	       RPC descriptor to send on
 * @param string       string to send
 *
 * @return	       0 is success, or error
 */
static int pack_string(struct rpc_desc *desc, const char *string)
{
	size_t len = strlen(string);
	int err;

	err = rpc_pack_type(desc, len);
	if (err)
		goto out;
	err = rpc_pack(desc, 0, string, len + 1);
out:
	return err;
}

/**
 * Helper function to receive a string
 *
 * @param desc	       RPC descriptor to receive from
 *
 * @return	       a valid string pointer or error. The string must be
 *		       freed with put_string.
 */
static char *unpack_get_string(struct rpc_desc *desc)
{
	size_t len;
	char *string;
	int err;

	err = rpc_unpack_type(desc, len);
	if (err)
		goto err;
	err = -ENOMEM;
	string = kmalloc(len + 1, GFP_KERNEL);
	if (!string)
		goto err;
	err = rpc_unpack(desc, 0, string, len + 1);
	if (err)
		goto err_string;
out:
	return string;

err_string:
	kfree(string);
err:
	string = ERR_PTR(err);
	goto out;
}

static void put_string(char *string)
{
	kfree(string);
}

/**
 * Generic function to broadcast a global directory operation
 * (mkdir, rmdir, symlink, unlink)
 *
 * @param op		op code of the operation
 * @param name		path to the target entry of the operation, from
 *			configfs scheduler subsystem directory.
 * @param old_name	target path for a symlink, or NULL
 *
 * @return		0 on success, or error
 */
static int global_config_dir_op(enum config_op op,
				const char *name, const char *old_name)
{
	struct rpc_desc *desc;
	krgnodemask_t nodes;
	int err;

	desc = global_config_op_begin(op, &nodes);
	if (IS_ERR(desc)) {
		err = PTR_ERR(desc);
		goto out;
	}
	err = pack_string(desc, name);
	if (err)
		goto err_cancel;
	if (!old_name) {
		BUG_ON(op == CO_SYMLINK);
		goto out_end;
	}
	BUG_ON(op != CO_SYMLINK);
	err = pack_string(desc, old_name);
	if (err)
		goto err_cancel;
out_end:
	err = global_config_op_end(desc, &nodes);
out:
	return err;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
	goto out;
}

static int handle_global_config_symlink(struct inode *dir,
					struct dentry *d_child,
					const char *old_name)
{
	struct path old_root;
	int err;

	/*
	 * Temporarily change current's root to configfs'one so that configfs
	 * can retrieve the right target item
	 */
	chroot_to_scheduler_subsystem(&old_root);
	err = vfs_symlink(d_child->d_parent->d_inode, d_child,
			  old_name);
	chroot_restore(&old_root);

	return err;
}

/**
 * Generic RPC handler for a global directory operation
 * (mkdir, rmdir, symlink, unlink)
 * The directory operation is made as if a user did the operation locally.
 */
static void handle_global_config_dir_op(struct rpc_desc *desc,
					void *_msg, size_t size)
{
	const struct config_op_message *msg = _msg;
	char *name;
	char *old_name = NULL;
	struct dentry *d_child;
	int err;

	name = unpack_get_string(desc);
	if (IS_ERR(name))
		goto err_name;

	d_child = get_child_dentry(name);
	if (IS_ERR(d_child)) {
		err = PTR_ERR(d_child);
		goto out_pack;
	}

	switch (msg->op) {
	case CO_MKDIR:
		err = vfs_mkdir(d_child->d_parent->d_inode, d_child, 0);
		break;
	case CO_RMDIR:
		err = vfs_rmdir(d_child->d_parent->d_inode, d_child);
		break;
	case CO_SYMLINK:
		old_name = unpack_get_string(desc);
		if (IS_ERR(old_name))
			goto err_old_name;

		err = handle_global_config_symlink(d_child->d_parent->d_inode,
						   d_child,
						   old_name);
		break;
	case CO_UNLINK:
		err = vfs_unlink(d_child->d_parent->d_inode, d_child);
		break;
	default:
		BUG();
	}

	put_child_dentry(d_child);

out_pack:
	rpc_pack_type(desc, err);
	put_string(old_name);
	put_string(name);
out:
	return;

err_old_name:
	put_child_dentry(d_child);
	put_string(name);
err_name:
	rpc_cancel(desc);
	goto out;
}

static void delayed_drop_work(struct work_struct *work);

/**
 * Initialize a global_config_item
 *
 * @param item		item to initialize
 * @param ops		operations associated with this item
 */
void global_config_item_init(
	struct global_config_item *item,
	const struct global_config_drop_operations *ops)
{
	INIT_DELAYED_WORK(&item->drop_work, delayed_drop_work);
	item->drop_ops = ops;
	item->path = NULL;
}

/**
 * Generic function to prepare a global config mkdir or symlink
 *
 * @param parent	item under which the operation is done
 * @param name		name of the new entry
 *
 * @return		a valid pointer or NULL, to be passed to create_end or
 *			create_error, or error
 */
static
struct string_list_object *create_begin(struct config_item *parent,
					const char *name)
{
	struct string_list_object *list;
	char *path;
	int err;

	if (current->flags & PF_KTHREAD)
		return NULL;

	err = global_lock_try_writelock(0);
	if (err)
		goto err_lock;

	path = get_full_path(parent, name);
	if (!path)
		goto err_path;

	list = hashed_string_list_lock_hash(global_items_set, path);
	BUG_ON(!list);
	if (IS_ERR(list))
		goto err_list;
	err = -EAGAIN;
	if (string_list_is_element(list, path))
		/* A previous drop is pending. Let it terminate. */
		goto err_is_element;
	kfree(path);
out:
	return list;
err_is_element:
	hashed_string_list_unlock_hash(global_items_set, list);
err_list:
	kfree(path);
err_path:
	global_lock_unlock(0);
err_lock:
	list = ERR_PTR(err);
	goto out;
}

/*
 * Same as create_end() below, except that concurrent operations are kept
 * disabled.
 * Caller is responsible for calling __create_end() afterwards.
 */
static int __create_commit(enum config_op op,
			   struct string_list_object *list,
			   struct config_item *parent,
			   struct global_config_item *item,
			   const char *name,
			   const char *old_name)
{
	char *path;
	int err;

	err = -ENOMEM;
	path = get_full_path(parent, name);
	if (!path)
		goto out;

	if (!list) {
		smp_read_barrier_depends();
		item->path = path;
		return 0;
	}

	err = string_list_add_element(list, path);
	if (err)
		goto err_list_add;

	err = global_config_dir_op(op, path, old_name);
	if (err)
		goto err_dir_op;

	item->path = path;

out:
	return err;

err_dir_op:
	global_config_dir_op(reverse_op(op), path, NULL);
	string_list_remove_element(list, path);
err_list_add:
	kfree(path);
	goto out;
}

/*
 * Last step of a global create. Re-enables concurrent operations.
 *
 * @param list		pointer returned by create_begin
 */
static void __create_end(struct string_list_object *list)
{
	if (list) {
		hashed_string_list_unlock_hash(global_items_set, list);
		global_lock_unlock(0);
	}
}

/**
 * Generic function to commit a global config mkdir or symlink
 *
 * @param op		op code of the operation
 * @param list		pointer returned by create_begin
 * @param parent	item under which the operation is done
 * @param item		pointer to the global_config_item for the new entry,
 *			previously initialized with global_config_item_init
 * @param name		name of the new entry
 * @param old_name	name of the target of a the symlink or NULL for mkdir
 *
 * @return		0 on success, or error
 */
static int create_end(enum config_op op,
		      struct string_list_object *list,
		      struct config_item *parent,
		      struct global_config_item *item,
		      const char *name,
		      const char *old_name)
{
	int err;

	err = __create_commit(op, list, parent, item, name, old_name);
	__create_end(list);

	return err;
}

/**
 * Generic function to cleanup a global config operation if an error occurs
 * before calling create_end
 *
 * @param list		pointer returned by create_begin
 * @param name		name of the new entry
 */
static void create_error(struct string_list_object *list,
			 const char *name)
{
	if (list) {
		hashed_string_list_unlock_hash(global_items_set, list);
		global_lock_unlock(0);
	}
}

/**
 * Function that prepares a global mkdir
 *
 * @param parent	item under which the operation is done
 * @param name		name of the new sub-directory
 *
 * @return		valid pointer or NULL to be passed to
 *			global_config_make_item_end or
 *			global_config_make_item_error, or error
 */
struct string_list_object *
global_config_make_item_begin(struct config_item *parent, const char *name)
{
	return create_begin(parent, name);
}

/*
 * Same as global_config_make_item_end() below, except that concurrent
 * operations are kept disabled.
 * Caller is responsible for calling __global_config_make_item_end() afterwards.
 */
int __global_config_make_item_commit(struct string_list_object *list,
				     struct config_item *parent,
				     struct global_config_item *item,
				     const char *name)
{
	return __create_commit(CO_MKDIR, list, parent, item, name, NULL);
}

/*
 * Last step of a global make_item. Re-enables concurrent operations.
 *
 * @param list		pointer returned by global_config_make_item_begin()
 */
void __global_config_make_item_end(struct string_list_object *list)
{
	__create_end(list);
}

/**
 * Commit a global config mkdir
 *
 * @param list		pointer returned by global_config_make_item_begin
 * @param parent	item under which the operation is done
 * @param item		pointer to the global_config_item for the new dir,
 *			previously initialized with global_config_item_init
 * @param name		name of the new dir
 *
 * @return		0 on success, or error
 */
int global_config_make_item_end(struct string_list_object *list,
				struct config_item *parent,
				struct global_config_item *item,
				const char *name)
{
	return create_end(CO_MKDIR, list, parent, item, name, NULL);
}

/**
 * Cleanup a global mkdir if an error occurs before calling
 * global_config_make_item_end
 *
 * @param list		pointer returned by global_config_make_item_begin
 * @param name		name of the new dir
 */
void global_config_make_item_error(struct string_list_object *list,
				   const char *name)
{
	create_error(list, name);
}

/**
 * Function that prepares a global symlink
 *
 * @param parent	item under which the link is created
 * @param name		name of the new link
 * @param target	target item of the new link
 *
 * @return		valid pointer or NULL to be passed to
 *			global_config_allow_link_end or
 *			global_config_allow_link_error, or error
 */
struct string_list_object *
global_config_allow_link_begin(struct config_item *parent,
				    const char *name,
				    struct config_item *target)
{
	return create_begin(parent, name);
}

/*
 * Same as global_config_allow_link_end() below, except that concurrent
 * operations are kept disabled.
 * Caller is responsible for calling __global_config_allow_link_end()
 * afterwards.
 */
int __global_config_allow_link_commit(struct string_list_object *list,
					   struct config_item *parent,
					   struct global_config_item *item,
					   const char *name,
					   struct config_item *target)
{
	char *path;
	int err;

	path = get_full_path(target, NULL);
	if (!path)
		return -ENOMEM;
	err = __create_commit(CO_SYMLINK, list, parent, item, name, path);
	put_path(path);

	return err;
}

/*
 * Last step of a global allow_link(). Re-enables concurrent operations.
 *
 * @param list		pointer returned by global_config_allow_link_begin()
 */
void __global_config_allow_link_end(struct string_list_object *list)
{
	__create_end(list);
}

/**
 * Commit a global config symlink
 *
 * @param list		pointer returned by global_config_allow_link_begin
 * @param parent	item under which the new link is created
 * @param item		pointer to the global_config_item for the new link,
 *			previously initialized with global_config_item_init
 * @param name		name of the new link
 * @param target	target item of the new link
 *
 * @return		0 on success, or error
 */
int global_config_allow_link_end(struct string_list_object *list,
				      struct config_item *parent,
				      struct global_config_item *item,
				      const char *name,
				      struct config_item *target)
{
	int err;

	err = __global_config_allow_link_commit(list,
						     parent,
						     item,
						     name,
						     target);
	__global_config_allow_link_end(list);

	return err;
}

/**
 * Cleanup a global symlink if an error occurs before calling
 * global_config_allow_link_end
 *
 * @param list		pointer returned by global_config_allow_link_begin
 * @param name		name of the new link
 * @param target	target item of the new link
 */
void global_config_allow_link_error(struct string_list_object *list,
					 const char *name,
					 struct config_item *target)
{
	create_error(list, name);
}

/*
 * Common handling of global rmdir and unlink
 *
 * Since rmdir and unlink cannot fail once configfs drop_item or drop_link
 * callbacks are called, we must repeatingly defer the global operation until we
 * manage to get the global lock.
 */

static struct timespec drop_delay = {
	.tv_sec = 1,
	.tv_nsec = 0
};

static void delay_drop(struct global_config_item *item)
{
	queue_delayed_work(krg_wq, &item->drop_work,
			   timespec_to_jiffies(&drop_delay));
}

static void put_item_path(struct global_config_item *item)
{
	char *path = item->path;
	item->path = NULL;
	/*
	 * Ensure that all conditions in item's create function that may become
	 * true after drop function see that assignment before setting another
	 * path (in __create_commit())
	 * This is needed when another node re-creates the item after having
	 * deleted it, because the local node takes no lock in both cases.
	 */
	smp_wmb();
	kfree(path);
}

static void drop(struct global_config_item *item)
{
	const struct global_config_drop_operations *drop_ops = item->drop_ops;
	char *name = item->path;
	struct string_list_object *list;
	int err;

	err = global_lock_try_writelock(0);
	if (err) {
		delay_drop(item);
		return;
	}

	list = hashed_string_list_lock_hash(global_items_set, name);
	BUG_ON(!list);
	if (IS_ERR(list))
		goto err_list;
	string_list_remove_element(list, name);

	if (drop_ops->is_symlink)
		global_config_dir_op(CO_UNLINK, name, NULL);
	else
		global_config_dir_op(CO_RMDIR, name, NULL);
	put_item_path(item);

	drop_ops->drop_func(item);

	hashed_string_list_unlock_hash(global_items_set, list);

out:
	global_lock_unlock(0);
	return;

err_list:
	delay_drop(item);
	goto out;
}

static void delayed_drop_work(struct work_struct *work)
{
	struct global_config_item *item =
		container_of(work,
			     struct global_config_item,
			     drop_work.work);

	drop(item);
}

/**
 * Notify a global rmdir or unlink. The drop may be delayed, so the item should
 * not be freed before the drop callback is called.
 *
 * @param item		global_config_item used for the dropped entry
 */
void global_config_drop(struct global_config_item *item)
{
	if (!(current->flags & PF_KTHREAD))
		/* Global drop */
		drop(item);
	else {
		/* Local drop */
		put_item_path(item);
		item->drop_ops->drop_func(item);
	}
}

/**
 * Prepare a global store operation on an attribute.
 *
 * @param item		item owning the attribute
 *
 * @return		a valid pointer or NULL to be passed to
 *			global_config_attr_store_end or
 *			global_config_attr_store_error, or error
 */
struct string_list_object *
global_config_attr_store_begin(struct config_item *item)
{
	struct string_list_object *list;
	char *path;

	if (current->flags & PF_KTHREAD)
		return NULL;

	path = get_full_path(item, NULL);
	if (!path)
		return ERR_PTR(-ENOMEM);
	list = hashed_string_list_lock_hash(global_items_set, path);
	BUG_ON(!list);
	put_path(path);

	return list;
}

/**
 * Commit a global store on an attribute
 *
 * @param list		pointer returned by global_config_attr_store_begin
 * @param item		item owning the attribute
 * @param attr		attribute to modify
 * @param page		buffer containing the value to store
 * @param count		number of bytes to store, as can really be stored
 *			(result from the local store operation for instance).
 *
 * @return		number of bytes written on success, or error
 */
ssize_t global_config_attr_store_end(struct string_list_object *list,
				     struct config_item *item,
				     struct configfs_attribute *attr,
				     const char *page, size_t count)
{
	struct rpc_desc *desc;
	krgnodemask_t nodes;
	char *path;
	ssize_t err = 0;

	if (!list)
		return count;

	if (!count)
		goto out_unlock;

	err = -ENOMEM;
	path = get_full_path(item, attr->ca_name);
	if (!path)
		goto out_unlock;

	desc = global_config_op_begin(CO_WRITE, &nodes);
	if (IS_ERR(desc)) {
		err = PTR_ERR(desc);
		goto out_free;
	}

	err = pack_string(desc, path);
	if (err)
		goto err_cancel;
	err = rpc_pack_type(desc, count);
	if (err)
		goto err_cancel;
	err = rpc_pack(desc, 0, page, count);
	if (err)
		goto err_cancel;

	err = global_config_op_end(desc, &nodes);
	if (!err)
		err = count;

out_free:
	put_path(path);
out_unlock:
	hashed_string_list_unlock_hash(global_items_set, list);
	return err;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
	goto out_free;
}

/**
 * RPC handler for global attribute store
 */
static void handle_global_config_write(struct rpc_desc *desc,
				       void *_msg, size_t size)
{
	struct path old_root;
	struct file *file;
	loff_t pos = 0;
	char *path;
	void *buf;
	size_t count;
	ssize_t ret;
	int err;

	path = unpack_get_string(desc);
	if (IS_ERR(path))
		goto err_path;
	err = rpc_unpack_type(desc, count);
	if (err)
		goto err_count;
	buf = kmalloc(count, GFP_KERNEL);
	if (!buf)
		goto err_count;
	err = rpc_unpack(desc, 0, buf, count);
	if (err)
		goto err_buf;

	chroot_to_scheduler_subsystem(&old_root);

	file = filp_open(path, O_WRONLY, 0);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto chroot_restore;
	}
	ret = vfs_write(file, buf, count, &pos);
	err = filp_close(file, NULL);

	if (ret != count) {
		if (ret >= 0)
			err = -ENOSPC;
		else
			err = ret;
	}
chroot_restore:
	chroot_restore(&old_root);

	rpc_pack_type(desc, err);

	kfree(buf);
	put_string(path);
out:
	return;

err_buf:
	kfree(buf);
err_count:
	put_string(path);
err_path:
	rpc_cancel(desc);
	goto out;
}

/**
 * Cleanup a global attribute store if an error occurs before calling
 * global_config_attr_store_end
 *
 * @param list		pointer returned by global_config_attr_store_begin
 * @param item		item owning the attribute
 */
void global_config_attr_store_error(struct string_list_object *list,
				    struct config_item *item)
{
	if (list)
		hashed_string_list_unlock_hash(global_items_set, list);
}

int global_config_pack_item(struct rpc_desc *desc, struct config_item *item)
{
	char *path = get_full_path(item, NULL);
	int err;

	if (!path)
		return -ENOMEM;
	err = pack_string(desc, path);
	put_path(path);

	return err;
}

static struct config_item *get_item(const char *path)
{
	struct config_group *parent;
	struct config_item *child;
	char *__path;
	char *parent_root, *next_root;

	child = &krg_scheduler_subsys.su_group.cg_item;
	/* Get rid of special case "/" */
	BUG_ON(!path[0]);
	if (!path[1])
		goto out;

	__path = kstrdup(path, GFP_KERNEL);
	if (!__path)
		return ERR_PTR(-ENOMEM);

	/*
	 * The algorithm to walk the tree is not safe for a general case
	 * configfs tree, but it is safe with krg_scheduler subtree since all
	 * directories are config_groups.
	 */

	parent_root = __path;

	mutex_lock(&krg_scheduler_subsys.su_mutex);
	do {
		parent = to_config_group(child);
		next_root = strchr(parent_root + 1, '/');
		if (next_root)
			*next_root = '\0';
		child = config_group_find_item(parent, parent_root + 1);
		if (!child)
			break;
		parent_root = next_root;
	} while (parent_root);
	if (child)
		config_item_get(child);
	mutex_unlock(&krg_scheduler_subsys.su_mutex);

	kfree(__path);
	if (!child)
		return ERR_PTR(-ENOENT);
out:
	return child;
}

struct config_item *global_config_unpack_get_item(struct rpc_desc *desc)
{
	struct config_item *item;
	char *path = unpack_get_string(desc);

	if (IS_ERR(path))
		return (struct config_item *) path;
	item = get_item(path);
	put_string(path);

	return item;
}

#ifdef CONFIG_KRG_EPM

int export_global_config_item(struct epm_action *action, ghost_t *ghost,
			      struct config_item *item)
{
	char *path = get_full_path(item, NULL);
	size_t len = strlen(path);
	int err;

	if (!path)
		return -ENOMEM;
	err = ghost_write(ghost, &len, sizeof(len));
	if (err)
		goto put;
	err = ghost_write(ghost, path, len + 1);
	if (err)
		goto put;
put:
	put_path(path);

	return err;
}

int import_global_config_item(struct epm_action *action, ghost_t *ghost,
			      struct config_item **item_p)
{
	struct config_item *item;
	char *path;
	size_t len;
	int err;

	err = ghost_read(ghost, &len, sizeof(len));
	if (err)
		goto out;
	err = -ENOMEM;
	path = kmalloc(len + 1, GFP_KERNEL);
	if (!path)
		goto out;
	err = ghost_read(ghost, path, len + 1);
	if (err)
		goto out_free;

	item = get_item(path);
	/*
	 * Do not set err if item is error, so that caller can distinguish ghost
	 * error from item lookup error
	 */
	*item_p = item;

out_free:
	kfree(path);
out:
	return err;
}

#endif /* CONFIG_KRG_EPM */

/**
 * Initialize the global config subsystem
 */
int global_config_start(void)
{
	struct file_system_type *fs_type;
	int err;

	/* retrieve a vfsmount structure for configfs */
	fs_type = get_fs_type("configfs");
	if (!fs_type)
		return -ENODEV;
	err = simple_pin_fs(fs_type, &scheduler_fs_mount, &mount_count);
	if (err)
		goto err_pin_fs;

	global_items_set = hashed_string_list_create(GLOBAL_CONFIG_KDDM_SET_ID);
	if (IS_ERR(global_items_set)) {
		err = PTR_ERR(global_items_set);
		goto err_set;
	}

	err = rpc_register_void(GLOBAL_CONFIG_OP, handle_global_config_op, 0);
	if (err)
		goto err_rpc;

out:
	return err;

err_rpc:

err_set:

	simple_release_fs(&scheduler_fs_mount, &mount_count);
err_pin_fs:
	goto out;
}

/**
 * Cleanup the global config subsystem.
 * Difficult to write indeed ...
 */
void global_config_exit(void)
{
}
