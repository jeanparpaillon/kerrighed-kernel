/** Kerrighed FAF servers.
 *  @file faf_server.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/syscalls.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/eventpoll.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/statfs.h>
#include <linux/remote_sleep.h>

#include <net/krgrpc/rpcid.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/remote_cred.h>
#include <kerrighed/physical_fs.h>
#include <kerrighed/file.h>
#include "../file_struct_io_linker.h"

#include "faf_internal.h"
#include "faf_server.h"
#include "faf_tools.h"
#include <kerrighed/faf_file_mgr.h>
#include "ruaccess.h"


/* Just a hint that must be > 0 */
#define FAF_POLL_NR_FD 1
static int faf_poll_epfd = -1;

struct faf_polled_fd {
	struct hlist_node list;
	unsigned long dvfs_id;
	struct hlist_head nodes;
	int count;
};

struct faf_polled_fd_node {
	struct hlist_node list;
	int count;
	kerrighed_node_t node_id;
};

#define FAF_POLLED_FD_HASH_SHIFT 8
#define FAF_POLLED_FD_HASH_SIZE (1 << FAF_POLLED_FD_HASH_SHIFT)
static struct hlist_head *faf_polled_fd_hash;
static DEFINE_MUTEX(faf_polled_fd_mutex);

#define FAF_POLL_EVENTS (POLLIN     | \
			 POLLOUT    | \
			 POLLPRI    | \
			 POLLRDNORM | \
			 POLLWRNORM | \
			 POLLRDBAND | \
			 POLLWRBAND | \
			 POLLRDHUP  | \
			 EPOLLET)
#define FAF_POLL_MAXEVENTS 10

static int unpack_path(struct rpc_desc *desc, struct path *path)
{
	char *tmp;
	int len, err;

	err = -ENOMEM;
	tmp = (char *)__get_free_page(GFP_KERNEL);
	if (!tmp)
		goto out;

	err = rpc_unpack_type(desc, len);
	if (err)
		goto out_free;
	err = rpc_unpack(desc, 0, tmp, len);
	if (err)
		goto out_free;

	err = kern_path(tmp, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, path);

out_free:
	free_page((unsigned long)tmp);

out:
	return err;
}

static int unpack_root(struct rpc_desc *desc, struct prev_root *prev_root)
{
	struct path root, tmp_root;
	int err;

	chroot_to_physical_root(prev_root);

	err = unpack_path(desc, &root);
	if (err) {
		chroot_to_prev_root(prev_root);
		return err;
	}

	write_lock(&current->fs->lock);
	tmp_root = current->fs->root;
	current->fs->root = root;
	write_unlock(&current->fs->lock);
	path_put(&tmp_root);

	return err;
}

static int unpack_root_pwd(struct rpc_desc *desc, struct prev_root *prev_root)
{
	struct path root, pwd, tmp_root, tmp_pwd;
	int err;

	chroot_to_physical_root(prev_root);

	err = unpack_path(desc, &root);
	if (err)
		goto out_err;
	err = unpack_path(desc, &pwd);
	if (err)
		goto out_err_pwd;

	write_lock(&current->fs->lock);
	tmp_root = current->fs->root;
	current->fs->root = root;
	tmp_pwd = current->fs->pwd;
	current->fs->pwd = pwd;
	write_unlock(&current->fs->lock);
	path_put(&tmp_root);
	path_put(&tmp_pwd);

	return err;

out_err_pwd:
	path_put(&root);
out_err:
	chroot_to_prev_root(prev_root);
	return err;
}

static int unpack_context(struct rpc_desc *desc, struct prev_root *prev_root,
			  const struct cred **old_cred)
{
	int err;

	*old_cred = unpack_override_creds(desc);
	if (IS_ERR(*old_cred))
		return PTR_ERR(*old_cred);

	err = unpack_root_pwd(desc, prev_root);
	if (err)
		revert_creds(*old_cred);

	return err;
}

static
void
restore_context(const struct prev_root *prev_root, const struct cred *old_cred)
{
	chroot_to_prev_root(prev_root);
	revert_creds(old_cred);
}

/** Handler for reading in a FAF open file.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_read(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_rw_msg *msg = msgIn;
	struct file *file = NULL;
	char *buf = NULL;
	long buf_size = PAGE_SIZE;
	ssize_t to_read, r;
	loff_t fpos;
	int err;

	err = remote_sleep_prepare(desc);
	if (err) {
		rpc_cancel(desc);
		return;
	}

	to_read = msg->count;
	fpos = msg->pos;

	r = -ENOMEM;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		goto error;

	file = fget(msg->server_fd);

	while (to_read > 0) {
		if (to_read < PAGE_SIZE)
			buf_size = to_read;

		r = vfs_read(file, buf, buf_size, &fpos);

		if (r > 0) {
			err = rpc_pack_type(desc, r);
			if (err)
				goto cancel;
			err = rpc_pack(desc, 0, buf, r);
			if (err)
				goto cancel;
		}

		/*
		 * Check if we have reach the end of the file
		 * or if there is an error
		 */
		if (r < buf_size)
			break;

		to_read -= r;
	}

error:
	/*
	 * Pack the end of transmission mark (0)
	 * or the error returned by vfs_read()
	 */
	if (r > 0)
		r = 0;
	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

	/* send the updated file position */
	err = rpc_pack_type(desc, fpos);
	if (err)
		goto cancel;

out:
	if (buf)
		kfree(buf);
	if (file)
		fput(file);

	remote_sleep_finish();
	return;

cancel:
	rpc_cancel(desc);
	goto out;
}

/** Handler for writing in a FAF open file.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_write(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_rw_msg *msg = msgIn;
	struct file *file = NULL;
	long to_recv;
	char *buf = NULL;
	ssize_t buf_size = PAGE_SIZE;
	ssize_t r, nr_received = -ENOMEM;
	loff_t fpos;
	int err;

	r = remote_sleep_prepare(desc);
	if (r) {
		rpc_cancel(desc);
		return;
	}

	to_recv = msg->count;
	fpos = msg->pos;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		goto error;

	nr_received = 0;

	file = fget(msg->server_fd);

	while (to_recv > 0) {
		err = rpc_unpack_type(desc, buf_size);
		if (err)
			goto cancel;

		/* copy_from_user has failed on the other side */
		if (buf_size < 0) {
			nr_received = buf_size;
			break;
		}

		err = rpc_unpack(desc, 0, buf, buf_size);
		if (err)
			goto cancel;

		r = vfs_write(file, buf, buf_size, &fpos);

		/* The last write failed. Break the write sequence */
		if (r < 0) {
			nr_received = r;
			break;
		}
		nr_received += r;
		to_recv -= buf_size;
	}

error:
	err = rpc_pack_type(desc, nr_received);
	if (err)
		goto cancel;

	/* send the updated file position */
	err = rpc_pack_type(desc, fpos);
	if (err)
		goto cancel;

out:
	if (buf)
		kfree(buf);
	if (file)
		fput(file);

	remote_sleep_finish();
	return;

cancel:
	rpc_cancel(desc);
	goto out;
}

static void handle_faf_readv(struct rpc_desc *desc, void *__msg, size_t size)
{
	struct faf_rw_msg *msg = __msg;
	struct faf_rw_ret ret;
	struct file *file;
	struct iovec *iov;
	int iovcnt, err;

	err = alloc_iov(&iov, &iovcnt, msg->count);
	if (err) {
		ret.ret = err;
		iov = NULL;
	}

	err = remote_sleep_prepare(desc);
	if (err)
		goto cancel;

	ret.pos = msg->pos;
	if (iov) {
		file = fget(msg->server_fd);
		ret.ret = vfs_readv(file, iov, iovcnt, &ret.pos);
		fput(file);
	}

	remote_sleep_finish();

	err = rpc_pack_type(desc, ret);
	if (err)
		goto cancel;
	if (ret.ret <= 0)
		goto out_free;

	err = send_iov(desc, iov, iovcnt, ret.ret, 0);
	if (err)
		goto cancel;

out_free:
	if (iov)
		free_iov(iov, iovcnt);

	return;

cancel:
	rpc_cancel(desc);
	goto out_free;
}

static void handle_faf_writev(struct rpc_desc *desc, void *__msg, size_t size)
{
	struct faf_rw_msg *msg = __msg;
	struct faf_rw_ret ret;
	struct file *file;
	struct iovec *iov;
	int iovcnt, err;

	err = alloc_iov(&iov, &iovcnt, msg->count);
	if (!err) {
		err = recv_iov(desc, iov, iovcnt, msg->count, 0);
		if (err)
			goto cancel;
	} else {
		ret.ret = err;
		iov = NULL;
	}

	err = remote_sleep_prepare(desc);
	if (err)
		goto cancel;

	ret.pos = msg->pos;
	if (iov) {
		file = fget(msg->server_fd);
		ret.ret = vfs_writev(file, iov, iovcnt, &ret.pos);
		fput(file);
	}

	remote_sleep_finish();

	err = rpc_pack_type(desc, ret);
	if (err)
		goto cancel;

out_free:
	if (iov)
		free_iov(iov, iovcnt);

	return;

cancel:
	rpc_cancel(desc);
	goto out_free;
}

static void handle_faf_getdents(struct rpc_desc *desc, void *__msg, size_t size)
{
	struct faf_getdents_msg *msg = __msg;
	const struct cred *old_cred = NULL;
	struct file *file;
	void *dirent = NULL;
	int err, err_rpc;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		old_cred = NULL;
		goto cancel;
	}

	dirent = kmalloc(msg->count, GFP_KERNEL);
	if (!dirent)
		goto cancel;

	file = fget(msg->server_fd);
	BUG_ON(!file);

	err = remote_sleep_prepare(desc);
	if (err)
		goto cancel;

	switch (msg->filler) {
	case OLDREADDIR:
		err = do_oldreaddir(file, dirent, msg->count);
		break;
	case GETDENTS:
		err = do_getdents(file, dirent, msg->count);
		break;
	case GETDENTS64:
		err = do_getdents64(file, dirent, msg->count);
		break;
	default:
		BUG();
		err = -EINVAL;
		break;
	}

	remote_sleep_finish();
	fput(file);

	err_rpc = rpc_pack_type(desc, err);
	if (err_rpc)
		goto cancel;

	if (err <= 0)
		goto out;

	/* err contains the used size of the buffer */
	err_rpc = rpc_pack(desc, 0, dirent, err);
	if (err_rpc)
		goto cancel;

out:
	if (old_cred)
		revert_creds(old_cred);

	if (dirent)
		kfree(dirent);

	return;

cancel:
	rpc_cancel(desc);
	goto out;
}

/** Handler for doing an IOCTL in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_ioctl(struct rpc_desc *desc,
		      void *msgIn, size_t size)
{
	struct faf_ctl_msg *msg = msgIn;
	struct prev_root prev_root;
	const struct cred *old_cred;
	long r;
	int err;

	err = unpack_context(desc, &prev_root, &old_cred);
	if (err) {
		rpc_cancel(desc);
		return;
	}

	err = remote_sleep_prepare(desc);
	if (err)
		goto out_err;

	err = prepare_ruaccess(desc);
	if (err)
		goto out_sleep_finish;

	r = sys_ioctl(msg->server_fd, msg->cmd, msg->arg);

	err = cleanup_ruaccess(desc);
	if (err)
		goto out_sleep_finish;

	err = rpc_pack_type(desc, r);

out_sleep_finish:
	remote_sleep_finish();
	if (err)
		goto out_err;

out:
	restore_context(&prev_root, old_cred);

	return;

out_err:
	rpc_cancel(desc);
	goto out;
}

/** Handler for doing an FCNTL in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_fcntl (struct rpc_desc* desc,
		       void *msgIn, size_t size)
{
	struct faf_ctl_msg *msg = msgIn;
	const struct cred *old_cred;
	unsigned long arg;
	long r;
	int err;

	if (msg->cmd == F_GETLK || msg->cmd == F_SETLK || msg->cmd == F_SETLKW)
		arg = (unsigned long) &msg->flock;
	else
		arg = msg->arg;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred))
		goto cancel;
	err = remote_sleep_prepare(desc);
	if (err) {
		revert_creds(old_cred);
		goto cancel;
	}

	r = sys_fcntl (msg->server_fd, msg->cmd, arg);

	remote_sleep_finish();
	revert_creds(old_cred);

	err = rpc_pack_type(desc, r);
	if (unlikely(err))
		goto cancel;

	if (!r && msg->cmd == F_GETLK) {
		err = rpc_pack_type(desc, msg->flock);
		if (unlikely(err))
			goto cancel;
	}

	return;
cancel:
	rpc_cancel(desc);
}

#if BITS_PER_LONG == 32
/** Handler for doing an FCNTL64 in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_fcntl64 (struct rpc_desc* desc,
			 void *msgIn, size_t size)
{
	struct faf_ctl_msg *msg = msgIn;
	const struct cred *old_cred;
	unsigned long arg;
	long r;
	int err;

	if (msg->cmd == F_GETLK64 || msg->cmd == F_SETLK64 || msg->cmd == F_SETLKW64)
		arg = (unsigned long) &msg->flock64;
	else
		arg = msg->arg;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred))
		goto cancel;
	err = remote_sleep_prepare(desc);
	if (err) {
		revert_creds(old_cred);
		goto cancel;
	}

	r = sys_fcntl64 (msg->server_fd, msg->cmd, arg);

	remote_sleep_finish();
	revert_creds(old_cred);

	err = rpc_pack_type(desc, r);
	if (unlikely(err))
		goto cancel;

	if (!r && msg->cmd == F_GETLK64) {
		err = rpc_pack_type(desc, msg->flock64);
		if (unlikely(err))
			goto cancel;
	}

	return;
cancel:
	rpc_cancel(desc);
}
#endif

/** Handler for doing an FSTAT in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_fstat (struct rpc_desc* desc,
		       void *msgIn, size_t size)
{
	struct kstat statbuf;
	struct faf_stat_msg *msg = msgIn;
	long r;
	int err;

	r = vfs_fstat(msg->server_fd, &statbuf);

	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

	err = rpc_pack_type(desc, statbuf);
	if (err)
		goto cancel;

	return;

cancel:
	rpc_cancel(desc);
}

/** Handler for doing an FSTATFS in a FAF open file.
 *  @author Matthieu Fertré
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
static void handle_faf_fstatfs(struct rpc_desc* desc,
			       void *msgIn, size_t size)
{
	struct statfs statbuf;
	struct faf_statfs_msg *msg = msgIn;
	long r;
	int err_rpc;

	r = sys_fstatfs(msg->server_fd, &statbuf);

	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	if (!r)
		err_rpc = rpc_pack_type(desc, statbuf);
err_rpc:
	if (err_rpc)
		rpc_cancel(desc);
}

/** Handler for seeking in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_lseek(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_seek_msg *msg = msgIn;
	off_t r = -EINVAL;
	int err;

	r = sys_lseek (msg->server_fd, msg->offset, msg->origin);

	err = rpc_pack_type(desc, r);
	if (err)
		rpc_cancel(desc);
}

/** Handler for seeking in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_llseek(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_llseek_msg *msg = msgIn;
	long r = -EINVAL;
	loff_t result;
	int err;

	r = sys_llseek (msg->server_fd, msg->offset_high, msg->offset_low,
			&result, msg->origin);

	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

	err = rpc_pack_type(desc, result);
	if (err)
		goto cancel;

	return;

cancel:
	rpc_cancel(desc);
}

/** Handler for syncing in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
int handle_faf_fsync (struct rpc_desc* desc,
                      void *msgIn, size_t size)
{
	struct faf_rw_msg *msg = msgIn;
	long r = -EINVAL;

	r = sys_fsync (msg->server_fd);

	return r;
}

void handle_faf_ftruncate(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_truncate_msg *msg = msgIn;
	long ret;
	int err;

#if BITS_PER_LONG == 32
	if (!msg->small)
		ret = sys_ftruncate64(msg->server_fd, msg->length);
	else
#endif
		ret = sys_ftruncate(msg->server_fd, msg->length);

	err = rpc_pack_type(desc, ret);
	if (err)
		rpc_cancel(desc);
}

/** Handler for locking in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_flock(struct rpc_desc *desc,
                      void *msgIn, size_t size)
{
	struct faf_ctl_msg *msg = msgIn;
	const struct cred *old_cred;
	long r = -EINVAL;
	int err;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred))
		goto cancel;
	r = remote_sleep_prepare(desc);
	if (r) {
		revert_creds(old_cred);
		goto cancel;
	}

	r = sys_flock (msg->server_fd, msg->cmd);

	remote_sleep_finish();
	revert_creds(old_cred);

	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

	return;

cancel:
	rpc_cancel(desc);
}

int handle_faf_fchmod(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_chmod_msg *msg = msgIn;
	const struct cred *old_cred;
	long ret;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		ret = PTR_ERR(old_cred);
		goto cancel;
	}

	ret = sys_fchmod(msg->server_fd, msg->mode);
	revert_creds(old_cred);

out:
	return ret;

cancel:
	rpc_cancel(desc);
	goto out;
}

int handle_faf_fchown(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_chown_msg *msg = msgIn;
	const struct cred *old_cred;
	long ret;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		ret = PTR_ERR(old_cred);
		goto cancel;
	}

	ret = sys_fchown(msg->server_fd, msg->user, msg->group);
	revert_creds(old_cred);

out:
	return ret;

cancel:
	rpc_cancel(desc);
	goto out;
}

void handle_faf_fallocate(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_allocate_msg *msg = msgIn;
	long ret;
	int err;

	ret = sys_fallocate(msg->server_fd, msg->mode, msg->offset, msg->len);

	err = rpc_pack_type(desc, ret);
	if (err)
		rpc_cancel(desc);
}

int handle_faf_utimes(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_utimes_msg *msg = msgIn;
	const struct cred *old_cred;
	struct timespec *times;
	long ret;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		ret = PTR_ERR(old_cred);
		goto cancel;
	}

	if (msg->times_not_null)
		times = msg->times;
	else
		times = NULL;

	ret = do_utimes(msg->server_fd, NULL, times, msg->flags);
	revert_creds(old_cred);

out:
	/*
	 * do_utimes returns a int converted to long, thus
	 * we can safely return it as an int.
	 */
	return ret;

cancel:
	rpc_cancel(desc);
	goto out;
}


/*
 * Handlers for polling a FAF open file.
 * @author Louis Rilling
 */
static void faf_poll_notify_node(kerrighed_node_t node, unsigned long dvfs_id)
{
	int err;

	err = rpc_async(RPC_FAF_POLL_NOTIFY, node, &dvfs_id, sizeof(dvfs_id));
	if (err)
		printk(KERN_WARNING "faf_poll_notify_node: "
		       "failed to notify node %d for %lu\n",
		       node, dvfs_id);
}

static struct faf_polled_fd *__faf_polled_fd_find(unsigned long dvfs_id);

static void faf_poll_notify_nodes(unsigned long dvfs_id)
{
	struct file *file;
	struct faf_polled_fd *polled_fd;
	struct faf_polled_fd_node *polled_fd_node;
	struct hlist_node *pos;

	file = lock_dvfs_file(dvfs_id);
	if (!file)
		goto out_put_dvfs_file;

	mutex_lock(&faf_polled_fd_mutex);

	polled_fd = __faf_polled_fd_find(dvfs_id);
	if (!polled_fd)
		goto out_unlock;

	hlist_for_each_entry(polled_fd_node, pos, &polled_fd->nodes, list)
		faf_poll_notify_node(polled_fd_node->node_id, dvfs_id);

out_unlock:
	mutex_unlock(&faf_polled_fd_mutex);

out_put_dvfs_file:
	unlock_dvfs_file(dvfs_id);
}

static int faf_poll_thread(void *arg)
{
	static struct epoll_event events[FAF_POLL_MAXEVENTS];
	int epfd = (int)(long)arg;
	long ret;
	int i;

	set_task_comm(current, "faf_poll");

	for (;;) {
		ret = sys_epoll_wait(epfd, events, FAF_POLL_MAXEVENTS, -1);
		BUG_ON(ret < 0);

		for (i = 0; i < ret; i++)
			faf_poll_notify_nodes((unsigned long)events[i].data);
	}

	return 0;
}

static int faf_poll_init_epfd(void)
{
	long pid;
	int epfd;

	if (faf_poll_epfd >= 0)
		goto out;

	epfd = (int) sys_epoll_create(FAF_POLL_NR_FD);
	if (epfd < 0)
		goto err_epfd;

	pid = kernel_thread(faf_poll_thread, (void *)(long)epfd, CLONE_FILES);
	if (pid < 0)
		goto err_thread;

	faf_poll_epfd = epfd;

out:
	return 0;

err_thread:
	sys_close(epfd);
	epfd = (int)pid;
err_epfd:
	return epfd;
}

static inline unsigned long faf_polled_fd_hashfn(unsigned long id)
{
	return hash_long(id, FAF_POLLED_FD_HASH_SHIFT);
}

static struct faf_polled_fd *__faf_polled_fd_find(unsigned long dvfs_id)
{
	struct faf_polled_fd *polled_fd;
	struct hlist_head *hash_list;
	struct hlist_node *pos;

	hash_list = &faf_polled_fd_hash[faf_polled_fd_hashfn(dvfs_id)];
	hlist_for_each_entry(polled_fd, pos, hash_list, list)
		if (polled_fd->dvfs_id == dvfs_id)
			return polled_fd;
	return NULL;
}

static struct faf_polled_fd *faf_polled_fd_find(unsigned long dvfs_id)
{
	struct faf_polled_fd *polled_fd;

	polled_fd = __faf_polled_fd_find(dvfs_id);
	if (polled_fd)
		goto out;

	polled_fd = kmalloc(sizeof(*polled_fd), GFP_KERNEL);
	if (!polled_fd)
		goto out;

	polled_fd->dvfs_id = dvfs_id;
	INIT_HLIST_HEAD(&polled_fd->nodes);
	polled_fd->count = 0;
	hlist_add_head(&polled_fd->list,
		       &faf_polled_fd_hash[faf_polled_fd_hashfn(dvfs_id)]);

out:
	return polled_fd;
}

static void faf_polled_fd_free(struct faf_polled_fd *polled_fd)
{
	BUG_ON(!hlist_empty(&polled_fd->nodes));
	BUG_ON(polled_fd->count);
	hlist_del(&polled_fd->list);
	kfree(polled_fd);
}

static
struct faf_polled_fd_node *
__faf_polled_fd_find_node(struct faf_polled_fd *polled_fd,
			  kerrighed_node_t node)
{
	struct faf_polled_fd_node *polled_fd_node;
	struct hlist_node *pos;

	hlist_for_each_entry(polled_fd_node, pos, &polled_fd->nodes, list)
		if (polled_fd_node->node_id == node)
			return polled_fd_node;
	return NULL;
}

static
struct faf_polled_fd_node *
faf_polled_fd_find_node(struct faf_polled_fd *polled_fd, kerrighed_node_t node)
{
	struct faf_polled_fd_node *polled_fd_node;

	polled_fd_node = __faf_polled_fd_find_node(polled_fd, node);
	if (polled_fd_node)
		goto out;

	polled_fd_node = kmalloc(sizeof(*polled_fd_node), GFP_KERNEL);
	if (!polled_fd_node)
		goto out;

	polled_fd_node->node_id = node;
	polled_fd_node->count = 0;
	hlist_add_head(&polled_fd_node->list, &polled_fd->nodes);
	polled_fd->count++;

out:
	return polled_fd_node;
}

static void faf_polled_fd_node_free(struct faf_polled_fd *polled_fd,
				    struct faf_polled_fd_node *polled_fd_node)
{
	BUG_ON(polled_fd_node->count);
	hlist_del(&polled_fd_node->list);
	polled_fd->count--;
	kfree(polled_fd_node);
}

static int faf_polled_fd_add(kerrighed_node_t client,
			     int server_fd,
			     unsigned long dvfs_id)
{
	struct faf_polled_fd *polled_fd;
	struct faf_polled_fd_node *polled_fd_node;
	struct epoll_event event;
	int err;

	mutex_lock(&faf_polled_fd_mutex);
	err = -ENOMEM;
	polled_fd = faf_polled_fd_find(dvfs_id);
	if (IS_ERR(polled_fd)) {
		err = PTR_ERR(polled_fd);
		goto err_polled_fd;
	}
	polled_fd_node = faf_polled_fd_find_node(polled_fd, client);
	if (!polled_fd_node)
		goto err_polled_fd_node;

	err = 0;
	polled_fd_node->count++;
	if (polled_fd_node->count > 1)
		/* Already polled by this node */
		goto out_unlock_polled_fd;
	if (polled_fd->count > 1)
		/* Already polled by another node */
		goto out_unlock_polled_fd;

	err = faf_poll_init_epfd();
	if (err)
		goto err_epoll_ctl;
	event.events = FAF_POLL_EVENTS;
	event.data = dvfs_id;
	err = sys_epoll_ctl(faf_poll_epfd, EPOLL_CTL_ADD, server_fd, &event);
	if (err)
		goto err_epoll_ctl;

out_unlock_polled_fd:
	mutex_unlock(&faf_polled_fd_mutex);

	return err;

err_epoll_ctl:
	polled_fd_node->count--;
	faf_polled_fd_node_free(polled_fd, polled_fd_node);
err_polled_fd_node:
	if (!polled_fd->count)
		faf_polled_fd_free(polled_fd);
err_polled_fd:
	printk(KERN_WARNING
	       "faf_polled_fd_add: failed to forward polling of %lu\n",
	       dvfs_id);
	goto out_unlock_polled_fd;
}

static int faf_polled_fd_remove(kerrighed_node_t client,
				int server_fd,
				unsigned long dvfs_id)
{
	struct file *file;
	struct faf_polled_fd *polled_fd;
	struct faf_polled_fd_node *polled_fd_node;
	int err;

	file = lock_dvfs_file(dvfs_id);
	mutex_lock(&faf_polled_fd_mutex);

	polled_fd = __faf_polled_fd_find(dvfs_id);
	BUG_ON(!polled_fd);
	BUG_ON(!polled_fd->count);
	polled_fd_node = __faf_polled_fd_find_node(polled_fd, client);
	BUG_ON(!polled_fd_node);
	BUG_ON(!polled_fd_node->count);

	polled_fd_node->count--;
	if (!polled_fd_node->count)
		faf_polled_fd_node_free(polled_fd, polled_fd_node);
	if (polled_fd->count)
		goto out_unlock;

	if (!file)
		/*
		 * The file is already closed or about to be closed. The last
		 * __fput() automatically removes it from the interest set of
		 * faf_poll_epfd.
		 */
		goto free_polled_fd;

	BUG_ON(faf_poll_epfd < 0);
	err = sys_epoll_ctl(faf_poll_epfd, EPOLL_CTL_DEL, server_fd, NULL);
	BUG_ON(err);

free_polled_fd:
	faf_polled_fd_free(polled_fd);

out_unlock:
	mutex_unlock(&faf_polled_fd_mutex);
	unlock_dvfs_file(dvfs_id);

	return 0;
}

static
void handle_faf_poll_wait(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct faf_poll_wait_msg *msg = _msg;
	struct file *file;
	unsigned int revents;
	int err, res = 0;

	if (msg->wait) {
		res = faf_polled_fd_add(desc->client,
					msg->server_fd,
					msg->objid);
		err = rpc_pack_type(desc, res);
		if (err)
			goto err;
	}

	file = fget(msg->server_fd);
	BUG_ON(!file);
	revents = file->f_op->poll(file, NULL);
	fput(file);

	err = rpc_pack_type(desc, revents);
	if (err)
		goto err;

	return;

err:
	if (msg->wait && !res)
		faf_polled_fd_remove(desc->client, msg->server_fd, msg->objid);
	rpc_cancel(desc);
}

static
void handle_faf_poll_dequeue(struct rpc_desc* desc, void *_msg, size_t size)
{
	struct faf_notify_msg *msg = _msg;

	faf_polled_fd_remove(desc->client, msg->server_fd, msg->objid);
}

static void faf_poll_init(void)
{
	int i;

	faf_polled_fd_hash = kmalloc(FAF_POLLED_FD_HASH_SIZE *
				     sizeof(*faf_polled_fd_hash),
				     GFP_KERNEL);
	if (!faf_polled_fd_hash)
		panic("Couldn't allocate FAF poll descriptor table!\n");
	for (i = 0; i < FAF_POLLED_FD_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&faf_polled_fd_hash[i]);

	rpc_register_void(RPC_FAF_POLL_WAIT, handle_faf_poll_wait, 0);
	rpc_register_void(RPC_FAF_POLL_DEQUEUE, handle_faf_poll_dequeue, 0);
}



/** Handler for d_path in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_d_path (struct rpc_desc* desc,
			void *msgIn, size_t size)
{
	struct faf_d_path_msg *msg = msgIn;
	char *buff, *file_name = NULL;
	struct file *file;
	struct prev_root prev_root;
	const struct cred *old_cred;
	bool deleted = false;
	int len;
	int err;

	old_cred = unpack_override_creds(desc);
	if (IS_ERR(old_cred)) {
		rpc_cancel(desc);
		return;
	}
	err = unpack_root(desc, &prev_root);
	if (err) {
		revert_creds(old_cred);
		rpc_cancel(desc);
		return;
	}

	buff = kmalloc (msg->count, GFP_KERNEL);

	file = fcheck_files (current->files, msg->server_fd);
	/* Remote caller holds a reference so it can't disappear. */
	BUG_ON(!file);
	if (msg->deleted)
		file_name = d_path_check(&file->f_path, buff, msg->count, &deleted);
	else
		file_name = d_path(&file->f_path, buff, msg->count);
	if (IS_ERR(file_name))
		len = PTR_ERR(file_name);
	else
		len = strlen(file_name) + 1;

	err = rpc_pack_type(desc, len);
	if (err)
		goto err_cancel;
	if (len >= 0) {
		err = rpc_pack(desc, 0, file_name, len);
		if (err)
			goto err_cancel;
		if (msg->deleted) {
			err = rpc_pack_type(desc, deleted);
			if (err)
				goto err_cancel;
		}
	}

out:
	kfree (buff);

	chroot_to_prev_root(&prev_root);
	revert_creds(old_cred);

	return;

err_cancel:
	rpc_cancel(desc);
	goto out;
}



int handle_faf_bind (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	struct prev_root prev_root;
	const struct cred *old_cred;
	int r;

	r = unpack_context(desc, &prev_root, &old_cred);
	if (r) {
		rpc_cancel(desc);
		return r;
	}

	r = sys_bind(msg->server_fd, (struct sockaddr *)&msg->sa, msg->addrlen);

	restore_context(&prev_root, old_cred);

	return r;
}

void handle_faf_connect(struct rpc_desc *desc,
			void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	struct prev_root prev_root;
	const struct cred *old_cred;
	int r, err;

	r = unpack_context(desc, &prev_root, &old_cred);
	if (r) {
		rpc_cancel(desc);
		return;
	}

	r = remote_sleep_prepare(desc);
	if (r)
		goto cancel;

	r = sys_connect(msg->server_fd,
			(struct sockaddr *)&msg->sa, msg->addrlen);

	remote_sleep_finish();

	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

out:
	restore_context(&prev_root, old_cred);

	return;

cancel:
	rpc_cancel(desc);
	goto out;
}

int handle_faf_listen (struct rpc_desc* desc,
		       void *msgIn, size_t size)
{
	struct faf_listen_msg *msg = msgIn;
	int r;

	r = sys_listen(msg->server_fd, msg->backlog);

	return r;
}

void handle_faf_accept (struct rpc_desc *desc,
		        void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	int err, r;
	struct file *file;

	r = remote_sleep_prepare(desc);
	if (r)
		goto err_cancel;

	r = sys_accept(msg->server_fd,
		       (struct sockaddr *)&msg->sa, &msg->addrlen);

	remote_sleep_finish();

	err = rpc_pack_type(desc, r);
	if (err)
		goto err_close_file;

	if (r < 0)
		return;

	file = fcheck_files(current->files, r);

	if (!file->f_objid) {
		err = create_kddm_file_object(file);
		if (err)
			goto err_close_file;
	}

	file->f_flags |= O_FAF_SRV;
	file->f_faf_srv_index = r;

	err = rpc_pack_type(desc, msg->addrlen);
	if (err)
		goto err_close_faf_file;

	err = rpc_pack(desc, 0, &msg->sa, msg->addrlen);
	if (err)
		goto err_close_faf_file;

	err = __send_faf_file_desc(desc, file);
	if (err)
		goto err_close_faf_file;

	err = rpc_unpack_type(desc, r);
	if (err)
		goto err_close_faf_file;

out:
	return;

err_cancel:
	rpc_cancel(desc);
	goto out;

err_close_faf_file:
	check_close_faf_srv_file(file);
	goto err_cancel;

err_close_file:
	if (r >= 0)
		sys_close(r);
	goto err_cancel;
}

int handle_faf_getsockname(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	struct prev_root prev_root;
	int r, err;

	err = unpack_root(desc, &prev_root);
	if (err)
		goto cancel;

	r = sys_getsockname(msg->server_fd,
			    (struct sockaddr *)&msg->sa, &msg->addrlen);

	err = rpc_pack_type(desc, msg->addrlen);
	if (err)
		goto cancel;

	err = rpc_pack(desc, 0, &msg->sa, msg->addrlen);
	if (err)
		goto cancel;

out:
	chroot_to_prev_root(&prev_root);
	return r;

cancel:
	r = err;
	rpc_cancel(desc);
	goto out;
}

int handle_faf_getpeername(struct rpc_desc* desc, void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	struct prev_root prev_root;
	int r, err;

	unpack_root(desc, &prev_root);

	r = sys_getpeername(msg->server_fd,
			    (struct sockaddr *)&msg->sa, &msg->addrlen);

	err = rpc_pack_type(desc, msg->addrlen);
	if (err)
		goto cancel;

	err = rpc_pack(desc, 0, &msg->sa, msg->addrlen);
	if (err)
		goto cancel;

out:
	chroot_to_prev_root(&prev_root);
	return r;

cancel:
	rpc_cancel(desc);
	goto out;
}

int handle_faf_shutdown (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_shutdown_msg *msg = msgIn;
	int r;

	r = sys_shutdown(msg->server_fd, msg->how);

	return r;
}

void handle_faf_setsockopt (struct rpc_desc *desc,
			    void *msgIn, size_t size)
{
	struct faf_setsockopt_msg *msg = msgIn;
	struct prev_root prev_root;
	const struct cred *old_cred;
	int r, err;

	err = unpack_context(desc, &prev_root, &old_cred);
	if (err) {
		rpc_cancel(desc);
		return;
	}

	err = prepare_ruaccess(desc);
	if (err)
		goto out_err;
	r = sys_setsockopt(msg->server_fd, msg->level, msg->optname,
			   msg->optval, msg->optlen);
	err = cleanup_ruaccess(desc);
	if (err)
		goto out_err;
	err = rpc_pack_type(desc, r);
	if (err)
		goto out_err;

exit:
	restore_context(&prev_root, old_cred);

	return;

out_err:
	rpc_cancel(desc);
	if (err > 0)
		err = -ENOMEM;
	r = err;
	goto exit;
}

void handle_faf_getsockopt (struct rpc_desc *desc,
			    void *msgIn, size_t size)
{
	struct faf_getsockopt_msg *msg = msgIn;
	struct prev_root prev_root;
	const struct cred *old_cred;
	int r, err;

	err = unpack_context(desc, &prev_root, &old_cred);
	if (err) {
		rpc_cancel(desc);
		return;
	}

	err = prepare_ruaccess(desc);
	if (err)
		goto out_err;
	r = sys_getsockopt(msg->server_fd, msg->level, msg->optname,
			   msg->optval, msg->optlen);
	err = cleanup_ruaccess(desc);
	if (err)
		goto out_err;
	err = rpc_pack_type(desc, r);
		goto out_err;

exit:
	restore_context(&prev_root, old_cred);

	return;

out_err:
	rpc_cancel(desc);
	if (err > 0)
		err = -ENOMEM;
	r = err;
	goto exit;
}

void handle_faf_sendmsg(struct rpc_desc *desc,
			void *msgIn, size_t size)
{
	struct faf_sendmsg_msg *msg = msgIn;
	ssize_t r;
	int err;
	struct msghdr msghdr;

	err = recv_msghdr(desc, &msghdr, msg->total_len, 0);
	if (err) {
		rpc_cancel(desc);
		return;
	}

	err = remote_sleep_prepare(desc);
	if (err)
		goto cancel;

	r = sys_sendmsg (msg->server_fd, &msghdr, msg->flags);

	remote_sleep_finish();

	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

out_free:
	free_msghdr(&msghdr);

	return;

cancel:
	rpc_cancel(desc);
	goto out_free;
}

void handle_faf_recvmsg(struct rpc_desc *desc,
			void *msgIn, size_t size)
{
	struct faf_sendmsg_msg *msg = msgIn;
	ssize_t r;
	int err;
	struct msghdr msghdr;

	err = recv_msghdr(desc, &msghdr, msg->total_len, MSG_HDR_ONLY);
	if (err) {
		rpc_cancel(desc);
		return;
	}

	err = remote_sleep_prepare(desc);
	if (err)
		goto cancel;

	r = sys_recvmsg(msg->server_fd, &msghdr, msg->flags);

	remote_sleep_finish();

	err = rpc_pack_type(desc, r);
	if (err)
		goto cancel;

	if (r < 0)
		goto out_free;

	/* Careful, client may have set MSG_TRUNC */
	err = send_msghdr(desc, &msghdr, min_t(size_t, r, msg->total_len), 0);
	if (err)
		goto cancel;

out_free:
	free_msghdr(&msghdr);

	return;

cancel:
	rpc_cancel(desc);
	goto out_free;
}

static void handle_faf_sendfile(struct rpc_desc *desc, void *_msg, size_t size)
{
	struct faf_sendfile_msg *msg = _msg;
	ssize_t retval;
	int err;

	retval = do_sendfile(msg->out_fd, msg->in_fd, &msg->ppos, msg->count,
			     msg->max);

	err = rpc_pack_type(desc, msg->ppos);
	if (err)
		goto cancel;

	err = rpc_pack_type(desc, retval);
	if (err)
		goto cancel;

	return;

cancel:
	rpc_cancel(desc);
}

int handle_faf_notify_close (struct rpc_desc* desc,
			     void *msgIn, size_t size)
{
	struct faf_notify_msg *msg = msgIn;
	struct file *file;

	spin_lock(&current->files->file_lock);
	file = fcheck_files(current->files, msg->server_fd);
	/* Check if the file has been closed locally before we receive the
	 * notification message.
	 */
	if (file && file->f_objid != msg->objid)
		file = NULL;
	if (file) {
		BUG_ON(!(file->f_flags & O_FAF_SRV));
		/*
		 * We cannot reliably call check_close_faf_srv_file() because
		 * file may be freed after spin_unlock().
		 */
		if (file_count(file) != 1)
			file = NULL;
	}
	spin_unlock(&current->files->file_lock);

	if (file)
		__check_close_faf_srv_file(msg->objid, file);

	return 0;
}

/* FAF handler Initialisation */
void faf_server_init (void)
{
	rpc_register_void(RPC_FAF_READ, handle_faf_read, 0);
	rpc_register_void(RPC_FAF_WRITE, handle_faf_write, 0);
	rpc_register_void(RPC_FAF_READV, handle_faf_readv, 0);
	rpc_register_void(RPC_FAF_WRITEV, handle_faf_writev, 0);
	rpc_register_void(RPC_FAF_GETDENTS, handle_faf_getdents, 0);
	faf_poll_init();
	rpc_register_void(RPC_FAF_IOCTL, handle_faf_ioctl, 0);
	rpc_register_void(RPC_FAF_FCNTL, handle_faf_fcntl, 0);

#if BITS_PER_LONG == 32
	rpc_register_void(RPC_FAF_FCNTL64, handle_faf_fcntl64, 0);
#endif

	rpc_register_void(RPC_FAF_FSTAT, handle_faf_fstat, 0);
	rpc_register_void(RPC_FAF_FSTATFS, handle_faf_fstatfs, 0);
	rpc_register_int(RPC_FAF_FSYNC, handle_faf_fsync, 0);
	rpc_register_void(RPC_FAF_FTRUNCATE, handle_faf_ftruncate, 0);
	rpc_register_void(RPC_FAF_FLOCK, handle_faf_flock, 0);
	rpc_register_int(RPC_FAF_FCHMOD, handle_faf_fchmod, 0);
	rpc_register_int(RPC_FAF_FCHOWN, handle_faf_fchown, 0);
	rpc_register_int(RPC_FAF_UTIMES, handle_faf_utimes, 0);
	rpc_register_void(RPC_FAF_LSEEK, handle_faf_lseek, 0);
	rpc_register_void(RPC_FAF_LLSEEK, handle_faf_llseek, 0);
	rpc_register_void(RPC_FAF_D_PATH, handle_faf_d_path, 0);

	rpc_register_int(RPC_FAF_BIND, handle_faf_bind, 0);
	rpc_register_void(RPC_FAF_CONNECT, handle_faf_connect, 0);
	rpc_register_int(RPC_FAF_LISTEN, handle_faf_listen, 0);
	rpc_register_void(RPC_FAF_ACCEPT, handle_faf_accept, 0);
	rpc_register_int(RPC_FAF_GETSOCKNAME, handle_faf_getsockname, 0);
	rpc_register_int(RPC_FAF_GETPEERNAME, handle_faf_getpeername, 0);
	rpc_register_int(RPC_FAF_SHUTDOWN, handle_faf_shutdown, 0);
	rpc_register_void(RPC_FAF_SETSOCKOPT, handle_faf_setsockopt, 0);
	rpc_register_void(RPC_FAF_GETSOCKOPT, handle_faf_getsockopt, 0);
	rpc_register_void(RPC_FAF_SENDMSG, handle_faf_sendmsg, 0);
	rpc_register_void(RPC_FAF_RECVMSG, handle_faf_recvmsg, 0);
	rpc_register_void(RPC_FAF_SENDFILE, handle_faf_sendfile, 0);
	rpc_register_int(RPC_FAF_NOTIFY_CLOSE, handle_faf_notify_close, 0);
}

/* FAF server Finalization */
void faf_server_finalize (void)
{
}
