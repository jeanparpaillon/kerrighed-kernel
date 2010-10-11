/** Kerrighed FAF Hooks.
 *  @file file_hooks.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/statfs.h>
#include <linux/types.h>
#include <linux/remote_sleep.h>
#include <kerrighed/faf.h>
#include <kerrighed/physical_fs.h>
#include <kerrighed/remote_cred.h>
#include <asm/uaccess.h>

#include <kddm/kddm.h>
#include <kerrighed/hotplug.h>
#include <net/krgrpc/rpc.h>
#include <net/krgrpc/rpcid.h>
#include <kerrighed/dvfs.h>
#include <kerrighed/file.h>
#include "../file_struct_io_linker.h"

#include "faf_internal.h"
#include "faf_server.h"
#include "faf_tools.h"
#include <kerrighed/faf_file_mgr.h>
#include "ruaccess.h"

static DEFINE_MUTEX(faf_poll_mutex);

static int pack_path(struct rpc_desc *desc, const struct path *path)
{
	char *tmp, *name;
	struct path phys_root;
	int len, err;

	err = -EPERM;
	get_physical_root(&phys_root);
	if (path->mnt->mnt_ns != phys_root.mnt->mnt_ns)
		/* path lives in a child mount namespace: not supported yet */
		goto out;

	err = -ENOMEM;
	tmp = (char *)__get_free_page(GFP_KERNEL);
	if (!tmp)
		goto out;

	err = -EINVAL;
	name = physical_d_path(path, tmp, false);
	if (!name)
		goto out_free;
	len = strlen(name) + 1;

	err = rpc_pack_type(desc, len);
	if (err)
		goto out_free;
	err = rpc_pack(desc, 0, name, len);

out_free:
	free_page((unsigned long)tmp);
out:
	path_put(&phys_root);

	return err;
}

static int pack_root(struct rpc_desc *desc)
{
	struct path root;
	int ret;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);

	ret = pack_path(desc, &root);

	path_put(&root);

	return ret;
}

static int pack_root_pwd(struct rpc_desc *desc)
{
	struct path root, pwd;
	int ret;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	pwd = current->fs->pwd;
	path_get(&pwd);
	read_unlock(&current->fs->lock);

	ret = pack_path(desc, &root);
	if (!ret)
		ret = pack_path(desc, &pwd);

	path_put(&root);
	path_put(&pwd);

	return ret;
}

static int pack_context(struct rpc_desc *desc)
{
	int err;

	err = pack_creds(desc, current_cred());
	if (err)
		goto out;
	err = pack_root_pwd(desc);

out:
	return err;
}

/** Kerrighed kernel hook for FAF lseek function.
 *  @author Renaud Lottiaux
 *
 *  @param file    File to seek in.
 *  @param offset  Offset to seek at.
 *  @param origin  Origin of the seek.
 */
off_t krg_faf_lseek(struct file * file, off_t offset, unsigned int origin)
{
	faf_client_data_t *data = file->private_data;
	struct faf_seek_msg msg;
	off_t r;
	struct rpc_desc* desc;
	int err;

	msg.server_fd = data->server_fd;
	msg.offset = offset;
	msg.origin = origin;

	desc = rpc_begin(RPC_FAF_LSEEK, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, r);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return r;
cancel:
	r = err;
	if (r == -ECANCELED)
		r = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

/** Kerrighed kernel hook for FAF llseek function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to seek in.
 *  @param offset_high   High part of the offset to seek at.
 *  @param offset_low    Low part of the offset to seek at.
 *  @param result        ...
 *  @param origin        Origin of the seek.
 */
long krg_faf_llseek(struct file *file,
		    unsigned long offset_high,
		    unsigned long offset_low,
		    loff_t * result,
		    unsigned int origin)
{
	faf_client_data_t *data = file->private_data;
	struct faf_llseek_msg msg;
	long r;
	struct rpc_desc* desc;
	int err;

	msg.server_fd = data->server_fd;
	msg.offset_high = offset_high;
	msg.offset_low = offset_low;
	msg.origin = origin;

	desc = rpc_begin(RPC_FAF_LLSEEK, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, r);
	if (err)
		goto cancel;

	err = rpc_unpack(desc, 0, result, sizeof(*result));
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return r;

cancel:
	r = err;
	if (r == -ECANCELED)
		r = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

/** Kerrighed kernel hook for FAF read function.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param file          File to read from.
 *  @param buf           Buffer to store data in.
 *  @param count         Number of bytes to read.
 *  @param pos           Offset to read from (updated at the end).
 */
ssize_t krg_faf_read(struct file * file, char *buf, size_t count, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	ssize_t nr;
	ssize_t received = 0;
	loff_t fpos;
	char *kbuff;
	int err;
	struct rpc_desc *desc;

	kbuff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuff)
		return -ENOMEM;

	msg.server_fd = data->server_fd;
	msg.count = count;
	msg.pos = *pos;

	nr = -ENOMEM;
	desc = rpc_begin(RPC_FAF_READ, data->server_id);
	if (!desc)
		goto out;

	/* Send read request */
	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;

	/* Get number of bytes to receive */
	err = unpack_remote_sleep_res_type(desc, nr);
	if (err)
		goto cancel;

	while (nr > 0) {
		/* Receive file data */
		err = rpc_unpack(desc, 0, kbuff, nr);
		if (err)
			goto cancel;
		err = copy_to_user(&buf[received], kbuff, nr);
		if (err) {
			nr = -EFAULT;
			break;
		}
		received += nr;
		err = unpack_remote_sleep_res_type(desc, nr);
		if (err)
			goto cancel;
	}

	if (!nr)
		/* no error occurs when reading */
		nr = received;

	/* Receive the updated offset */
	err = rpc_unpack_type(desc, fpos);
	if (err)
		goto cancel;
	*pos = fpos;

out_end:
	rpc_end(desc, 0);

out:
	kfree(kbuff);

	return nr;

cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -EIO;
	nr = err;
	goto out_end;
}

/** Kerrighed kernel hook for FAF write function.
 *  @author Renaud Lottiaux, Matthieu Fertré
 *
 *  @param file          File to write to.
 *  @param buf           Buffer of data to write.
 *  @param count         Number of bytes to write.
 *  @param pos           Offset to write from (updated at the end).
 */
ssize_t krg_faf_write(struct file * file, const char *buf,
		      size_t count, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	ssize_t buf_size = PAGE_SIZE, nr;
	long offset = 0;
	long to_send = count;
	loff_t fpos;
	char *kbuff;
	int err;
	struct rpc_desc *desc;

	kbuff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuff)
		return -ENOMEM;

	msg.server_fd = data->server_fd;
	msg.count = count;
	msg.pos = *pos;

	nr = -ENOMEM;
	desc = rpc_begin(RPC_FAF_WRITE, data->server_id);
	if (!desc)
		goto out;

	/* Send write request */
	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;

	while (to_send > 0) {
		if (to_send < PAGE_SIZE)
			buf_size = to_send;

		err = copy_from_user(kbuff, &buf[offset], buf_size);
		if (err)
			buf_size = -EFAULT;

		err = rpc_pack_type(desc, buf_size);
		if (err)
			goto cancel;

		if (buf_size < 0) /* copy_from_user has failed */
			break;

		err = rpc_pack(desc, 0, kbuff, buf_size);
		if (err)
			goto cancel;

		to_send -= buf_size;
		offset += buf_size;
	}

	err = unpack_remote_sleep_res_type(desc, nr);
	if (err)
		nr = err;
	else if (nr == -EPIPE)
		send_sig(SIGPIPE, current, 0);

	/* Receive the updated offset */
	err = rpc_unpack_type(desc, fpos);
	if (err)
		goto cancel;
	*pos = fpos;

out_end:
	rpc_end(desc, 0);

out:
	kfree(kbuff);

	return nr;

cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -EIO;
	nr = err;
	goto out_end;
}

ssize_t krg_faf_readv(struct file *file, const struct iovec __user *vec,
		      unsigned long vlen, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	struct faf_rw_ret ret;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	int iovcnt;
	size_t total_len;
	struct rpc_desc *desc;
	int err;

	ret.ret = rw_copy_check_uvector(READ, vec, vlen,
					ARRAY_SIZE(iovstack), iovstack, &iov);
	if (ret.ret < 0)
		return ret.ret;
	iovcnt = vlen;
	total_len = ret.ret;

	ret.ret = -ENOMEM;
	desc = rpc_begin(RPC_FAF_READV, data->server_id);
	if (!desc)
		goto out;

	msg.server_fd = data->server_fd;
	msg.count = total_len;
	msg.pos = *pos;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, ret);
	if (err)
		goto cancel;

	*pos = ret.pos;
	if (ret.ret <= 0)
		goto out_end;

	err = recv_iov(desc, iov, iovcnt, ret.ret, MSG_USER);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);

out:
	if (iov != iovstack)
		kfree(iov);

	return ret.ret;

cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -EIO;
	ret.ret = err;
	goto out_end;
}

ssize_t krg_faf_writev(struct file *file, const struct iovec __user *vec,
		       unsigned long vlen, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	struct faf_rw_ret ret;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	int iovcnt;
	size_t total_len;
	struct rpc_desc *desc;
	int err;

	ret.ret = rw_copy_check_uvector(WRITE, vec, vlen,
					ARRAY_SIZE(iovstack), iovstack, &iov);
	if (ret.ret < 0)
		return ret.ret;
	iovcnt = vlen;
	total_len = ret.ret;

	ret.ret = -ENOMEM;
	desc = rpc_begin(RPC_FAF_WRITEV, data->server_id);
	if (!desc)
		goto out;

	msg.server_fd = data->server_fd;
	msg.count = total_len;
	msg.pos = *pos;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = send_iov(desc, iov, iovcnt, total_len, MSG_USER);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, ret);
	if (err)
		goto cancel;

	*pos = ret.pos;
	if (ret.ret == -EPIPE)
		send_sig(SIGPIPE, current, 0);

out_end:
	rpc_end(desc, 0);

out:
	if (iov != iovstack)
		kfree(iov);

	return ret.ret;

cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -EIO;
	ret.ret = err;
	goto out_end;
}

int krg_faf_getdents(struct file *file, enum getdents_filler filler,
		     void *dirent, unsigned int count)
{
	faf_client_data_t *data = file->private_data;
	struct faf_getdents_msg msg;
	struct rpc_desc *desc;
	int err, err_rpc;

	err = -ENOMEM;
	desc = rpc_begin(RPC_FAF_GETDENTS, data->server_id);
	if (!desc)
		goto out;

	msg.server_fd = data->server_fd;
	msg.filler = filler;
	msg.count = count;

	err_rpc = rpc_pack_type(desc, msg);
	if (err_rpc)
		goto cancel;

	err_rpc = pack_creds(desc, current_cred());
	if (err_rpc)
		goto cancel;

	err_rpc = unpack_remote_sleep_res_prepare(desc);
	if (err_rpc)
		goto cancel;

	err_rpc = unpack_remote_sleep_res_type(desc, err);
	if (err_rpc)
		goto cancel;

	if (err <= 0)
		goto out_end;

	/* err contains the used size of the buffer */
	err_rpc = rpc_unpack(desc, 0, dirent, err);

	if (err_rpc)
		goto cancel;

out_end:
	rpc_end(desc, 0);

out:
	return err;

cancel:
	rpc_cancel(desc);
	err = err_rpc;
	goto out;
}

/** Kerrighed kernel hook for FAF ioctl function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do an ioctl to.
 *  @param cmd           IOCTL command.
 *  @param arg           IOCTL argument.
 */
long krg_faf_ioctl (struct file *file,
		    unsigned int cmd,
		    unsigned long arg)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	long r;
	struct rpc_desc *desc;
	int err;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;
	msg.arg = arg;

	err = -ENOMEM;
	desc = rpc_begin(RPC_FAF_IOCTL, data->server_id);
	if (!desc)
		goto out_err;

	err = rpc_pack_type(desc, msg);
	if (err)
		goto out_cancel;
	err = pack_context(desc);
	if (err)
		goto out_cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto out_cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto out_cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto out_cancel;
	rpc_end(desc, 0);

out:
	return r;

out_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
	if (err > 0)
		err = -ENOMEM;
out_err:
	r = err;
	goto out;
}

/** Kerrighed kernel hook for FAF fcntl function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do an fcntl to.
 *  @param cmd           FCNTL command.
 *  @param arg           FCNTL argument.
 */
long krg_faf_fcntl (struct file *file,
		    unsigned int cmd,
		    unsigned long arg)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	struct rpc_desc *desc;
	int err;
	long r;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;
	r = -EFAULT;
	if ((cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK)
	    && copy_from_user(&msg.flock,
			      (struct flock __user *) arg, sizeof(msg.flock)))
			goto out;
	else
		msg.arg = arg;

	r = -ENOLCK;
	desc = rpc_begin(RPC_FAF_FCNTL, data->server_id);
	if (unlikely(!desc))
		goto out;

	err = rpc_pack_type(desc, msg);
	if (unlikely(err))
		goto cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (unlikely(err))
		goto cancel;

	if (!r && cmd == F_GETLK) {
		err = rpc_unpack_type(desc, msg.flock);
		if (unlikely(err))
			goto cancel;
		r = -EFAULT;
		if (!copy_to_user((struct flock __user *) arg,
				  &msg.flock, sizeof(msg.flock)))
			r = 0;
	}

out_end:
	rpc_end(desc, 0);

out:
	return r;

cancel:
	rpc_cancel(desc);
	goto out_end;
}

#if BITS_PER_LONG == 32
/** Kerrighed kernel hook for FAF fcntl64 function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do an fcntl to.
 *  @param cmd           FCNTL command.
 *  @param arg           FCNTL argument.
 */
long krg_faf_fcntl64 (struct file *file,
		      unsigned int cmd,
		      unsigned long arg)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	long r;
	struct rpc_desc* desc;
	int err;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;
	r = -EFAULT;
	if ((cmd == F_GETLK64 || cmd == F_SETLK64 || cmd == F_SETLKW64)
	    && copy_from_user(&msg.flock64,
			      (struct flock64 __user *) arg, sizeof(msg.flock64)))
			goto out;
	else
		msg.arg = arg;

	r = -ENOLCK;
	desc = rpc_begin(RPC_FAF_FCNTL64,
			 data->server_id);
	if (unlikely(!desc))
		goto out;

	err = rpc_pack_type(desc, msg);
	if (unlikely(err))
		goto cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (unlikely(err))
		goto cancel;

	if (!r && cmd == F_GETLK64) {
		err = rpc_unpack_type(desc, msg.flock64);
		if (unlikely(err))
			goto cancel;
		r = -EFAULT;
		if (!copy_to_user((struct flock64 __user *) arg,
				  &msg.flock64, sizeof(msg.flock64)))
			r = 0;
	}

out_end:
	rpc_end(desc, 0);

out:
	return r;

cancel:
	rpc_cancel(desc);
	goto out_end;
}
#endif

/** Kerrighed kernel hook for FAF fstat function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do an fcntl to.
 *  @param statbuf       Kernel buffer to store file stats.
 */
long krg_faf_fstat(struct file *file, struct kstat *statbuf)
{
	struct kstat buffer;
	faf_client_data_t *data = file->private_data;
	struct faf_stat_msg msg;
	long r;
	struct rpc_desc* desc;
	int err;

	msg.server_fd = data->server_fd;

	desc = rpc_begin(RPC_FAF_FSTAT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, r);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, buffer);
	if (err)
		goto cancel;

	*statbuf = buffer;

out_end:
	rpc_end(desc, 0);
out:
	return r;

cancel:
	r = err;
	if (r == -ECANCELED)
		r = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

/** Kerrighed kernel hook for FAF fstat function.
 *  @author Matthieu Fertré
 *
 *  @param file          File to do an fcntl to.
 *  @param statbuf       Kernel buffer to store file stats.
 */
long krg_faf_fstatfs(struct file *file,
		     struct statfs *statfsbuf)
{
	struct statfs buffer;
	faf_client_data_t *data = file->private_data;
	struct faf_statfs_msg msg;
	long r;
	int err;
	struct rpc_desc *desc;

	msg.server_fd = data->server_fd;

	desc = rpc_begin(RPC_FAF_FSTATFS, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, r);
	if (err)
		goto cancel;

	if (r)
		goto out_end;

	err = rpc_unpack_type(desc, buffer);
	if (err)
		goto cancel;

	*statfsbuf = buffer;

out_end:
	rpc_end(desc, 0);
out:
	return r;

cancel:
	r = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

/** Kerrighed kernel hook for FAF fsync function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do a fsync to.
 */
long krg_faf_fsync (struct file *file)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	long r;

	msg.server_fd = data->server_fd;

	r = rpc_sync(RPC_FAF_FSYNC, data->server_id, &msg, sizeof(msg));

	return r;
}

/** Kerrighed kernel hook for FAF flock function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do a flock to.
 */
long krg_faf_flock (struct file *file,
		    unsigned int cmd)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	struct rpc_desc *desc;
	long r;
	int err;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;

	desc = rpc_begin(RPC_FAF_FLOCK, data->server_id);
	if (!desc)
		return -ENOMEM;

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
	return r;

cancel:
	rpc_cancel(desc);
	r = err;
	goto out_end;
}

long krg_faf_ftruncate(struct file *file, loff_t length, int small)
{
	faf_client_data_t *data = file->private_data;
	struct faf_truncate_msg msg;
	struct rpc_desc *desc;
	int err;
	long ret;

	msg.server_fd = data->server_fd;
	msg.length = length;
	msg.small = small;

	desc = rpc_begin(RPC_FAF_FTRUNCATE, data->server_id);
	if (!desc) {
		ret = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, ret);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return ret;
cancel:
	ret = err;
	if (ret == -ECANCELED)
		ret = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

int krg_faf_fchmod(struct file *file, mode_t mode)
{
	faf_client_data_t *data = file->private_data;
	struct faf_chmod_msg msg;
	struct rpc_desc *desc;
	int ret, err;

	msg.server_fd = data->server_fd;
	msg.mode = mode;

	desc = rpc_begin(RPC_FAF_FCHMOD, data->server_id);
	if (!desc) {
		ret = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, ret);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return ret;
cancel:
	ret = err;
	if (ret == -ECANCELED)
		ret = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

int krg_faf_fchown(struct file *file, uid_t user, gid_t group)
{
	faf_client_data_t *data = file->private_data;
	struct faf_chown_msg msg;
	struct rpc_desc *desc;
	int ret, err;

	msg.server_fd = data->server_fd;
	msg.user = user;
	msg.group = group;

	desc = rpc_begin(RPC_FAF_FCHOWN, data->server_id);
	if (!desc) {
		ret = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, ret);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return ret;
cancel:
	ret = err;
	if (ret == -ECANCELED)
		ret = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

long krg_faf_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_allocate_msg msg;
	struct rpc_desc *desc;
	int err;
	long ret;

	msg.server_fd = data->server_fd;
	msg.mode = mode;
	msg.offset = offset;
	msg.len = len;

	desc = rpc_begin(RPC_FAF_FALLOCATE, data->server_id);
	if (!desc) {
		ret = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, ret);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return ret;
cancel:
	ret = err;
	if (ret == -ECANCELED)
		ret = -EIO;
	rpc_cancel(desc);
	goto out_end;
}

static char *__krg_faf_d_path(const struct path *root, const struct file *file,
			      char *buff, int size, bool *deleted)
{
	faf_client_data_t *data = file->private_data;
	struct faf_d_path_msg msg;
	struct rpc_desc* desc;
	int len;
	int err;

	BUG_ON(file->f_flags & O_FAF_SRV);

	msg.server_fd = data->server_fd;
	msg.deleted = !!deleted;
	msg.count = size;

	desc = rpc_begin(RPC_FAF_D_PATH, data->server_id);
	if (!desc)
		return ERR_PTR(-ENOMEM);
	err = rpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto err_cancel;
	err = pack_path(desc, root);
	if (err)
		goto err_cancel;

	err = rpc_unpack_type(desc, len);
	if (err)
		goto err_cancel;
	if (len >= 0) {
		err = rpc_unpack(desc, 0, buff, len);
		if (err)
			goto err_cancel;
		if (deleted) {
			err = rpc_unpack_type(desc, *deleted);
			if (err)
				goto err_cancel;
		}
	} else {
		buff = ERR_PTR(len);
	}
out_end:
	rpc_end(desc, 0);

	return buff;

err_cancel:
	rpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	buff = ERR_PTR(err);
	goto out_end;
}

char *krg_faf_phys_d_path(const struct file *file, char *buff, int size,
			  bool *deleted)
{
	struct path root;
	char *ret;

	get_physical_root(&root);
	ret = __krg_faf_d_path(&root, file, buff, size, deleted);
	path_put(&root);

	return ret;
}

/** Kerrighed FAF d_path function.
 *  @author Renaud Lottiaux
 *
 *  @param file     The file to get the path.
 *  @param buff     Buffer to store the path in.
 */
char *
krg_faf_d_path(const struct file *file, char *buff, int size, bool *deleted)
{
	struct path root;
	char *ret;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);

	ret = __krg_faf_d_path(&root, file, buff, size, deleted);

	path_put(&root);

	return ret;
}

int krg_faf_do_path_lookup(struct file *file,
			   const char *name,
			   unsigned int flags,
			   struct nameidata *nd)
{
	char *tmp = (char *) __get_free_page (GFP_KERNEL);
	char *path;
	bool deleted;
	int len, err = 0;

	path = krg_faf_d_path(file, tmp, PAGE_SIZE, &deleted);

	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		goto exit;
	}
	if (deleted) {
		err = -ENOENT;
		goto exit;
	}


	if (likely(path != tmp)) {
		strncpy(tmp, path, PAGE_SIZE);
		path = tmp;
	}

	len = strlen (path);
	strncpy(&path[len], name, PAGE_SIZE - len);

	err = path_lookup(path, flags, nd);
exit:
	free_page ((unsigned long) tmp);
	return err;
}

long krg_faf_bind (struct file * file,
		   struct sockaddr __user *umyaddr,
		   int addrlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct rpc_desc *desc;
	int err, r;

	msg.server_fd = data->server_fd;

	r = move_addr_to_kernel(umyaddr, addrlen, (struct sockaddr *)&msg.sa);
	if (r)
		goto out;

	msg.addrlen = addrlen;

	r = -ENOMEM;
	desc = rpc_begin(RPC_FAF_BIND, data->server_id);
	if (!desc)
		goto out;

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;
	err = pack_context(desc);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, r);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return r;

cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -EPIPE;
	r = err;
	goto out_end;
}



long krg_faf_connect (struct file * file,
		      struct sockaddr __user *uservaddr,
		      int addrlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct rpc_desc *desc;
	int r, err;

	msg.server_fd = data->server_fd;

	r = move_addr_to_kernel(uservaddr, addrlen, (struct sockaddr *)&msg.sa);
	if (r)
		goto out;

	msg.addrlen = addrlen;

	desc = rpc_begin(RPC_FAF_CONNECT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;
	err = pack_context(desc);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);

out:
	return r;

cancel:
	rpc_cancel(desc);
	r = err;
	goto out_end;
}

long krg_faf_listen (struct file * file,
		     int backlog)
{
	faf_client_data_t *data = file->private_data;
	struct faf_listen_msg msg;
	int r;

	msg.server_fd = data->server_fd;

	msg.backlog = backlog;

	r = rpc_sync(RPC_FAF_LISTEN, data->server_id, &msg, sizeof(msg));

	return r;
}

long krg_faf_accept(struct file * file,
		    struct sockaddr __user *upeer_sockaddr,
		    int __user *upeer_addrlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	int r, err;
	struct sockaddr_storage sa;
	int sa_len;
	struct file *newfile;
	int fd;
	struct rpc_desc* desc;

	BUG_ON (data->server_id == kerrighed_node_id);

	fd = get_unused_fd();
	if (fd < 0) {
		r = fd;
		goto out;
	}

	msg.server_fd = data->server_fd;

	if (upeer_sockaddr) {
		if (get_user(msg.addrlen, upeer_addrlen)) {
			r = -EFAULT;
			goto out_put_fd;
		}
	} else {
		msg.addrlen = 0;
	}

	desc = rpc_begin(RPC_FAF_ACCEPT, data->server_id);
	if (!desc)
		goto out_put_fd;

	r = rpc_pack_type(desc, msg);
	if (r)
		goto err_cancel;

	r = unpack_remote_sleep_res_prepare(desc);
	if (r)
		goto err_cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err) {
		r = err;
		goto err_cancel;
	}

	if (r<0) {
		rpc_end(desc, 0);
		goto out_put_fd;
	}

	r = rpc_unpack_type(desc, sa_len);
	if (r)
		goto err_cancel;

	r = rpc_unpack(desc, 0, &sa, sa_len);
	if (r)
		goto err_cancel;

	newfile = rcv_faf_file_desc(desc);
	if (IS_ERR(newfile)) {
		r = PTR_ERR(newfile);
		goto err_cancel;
	}

	/*
	 * We have enough to clean up the new file ourself if needed. Tell it
	 * to the server.
	 */
	r = rpc_pack_type(desc, fd);
	if (r)
		goto err_close_faf_file;

	rpc_end(desc, 0);

	if (upeer_sockaddr) {
		r = move_addr_to_user((struct sockaddr *)&sa, sa_len,
				      upeer_sockaddr, upeer_addrlen);
		if (r)
			goto err_close_faf_file;
	}

	fd_install(fd, newfile);
	r = fd;

out:
	return r;

err_cancel:
	rpc_cancel(desc);
	rpc_end(desc, 0);
out_put_fd:
	put_unused_fd(fd);
	goto out;

err_close_faf_file:
	fput(newfile);
	goto out_put_fd;
}

long krg_faf_getsockname (struct file * file,
			  struct sockaddr __user *usockaddr,
			  int __user *usockaddr_len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct sockaddr_storage sa;
	int sa_len;
	struct rpc_desc *desc;
	int r = -EFAULT;

	msg.server_fd = data->server_fd;
	if (get_user(msg.addrlen, usockaddr_len))
		goto out;

	desc = rpc_begin(RPC_FAF_GETSOCKNAME, data->server_id);
	rpc_pack_type(desc, msg);
	pack_root(desc);

	rpc_unpack_type(desc, r);
	rpc_unpack_type(desc, sa_len);
	rpc_unpack(desc, 0, &sa, sa_len);
	rpc_end(desc, 0);

	if (!r)
		r = move_addr_to_user((struct sockaddr *)&sa, sa_len,
				      usockaddr, usockaddr_len);

out:
	return r;
}

long krg_faf_getpeername (struct file * file,
			  struct sockaddr __user *usockaddr,
			  int __user *usockaddr_len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct sockaddr_storage sa;
	int sa_len;
	struct rpc_desc *desc;
	int r;

	msg.server_fd = data->server_fd;

	if (get_user(msg.addrlen, usockaddr_len))
		return -EFAULT;

	desc = rpc_begin(RPC_FAF_GETPEERNAME, data->server_id);
	rpc_pack_type(desc, msg);
	pack_root(desc);
	rpc_unpack_type(desc, r);
	rpc_unpack_type(desc, sa_len);
	rpc_unpack(desc, 0, &sa, sa_len);
	rpc_end(desc, 0);

	if (!r)
		r = move_addr_to_user((struct sockaddr *)&sa, sa_len,
				      usockaddr, usockaddr_len);

	return r;
}

long krg_faf_shutdown (struct file * file,
		       int how)
{
	faf_client_data_t *data = file->private_data;
	struct faf_shutdown_msg msg ;
	int r;

	msg.server_fd = data->server_fd;

	msg.how = how;

	r = rpc_sync(RPC_FAF_SHUTDOWN, data->server_id, &msg, sizeof(msg));

	return r;
}

long krg_faf_setsockopt (struct file * file,
			 int level,
			 int optname,
			 char __user *optval,
			 int optlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_setsockopt_msg msg;
	struct rpc_desc *desc;
	int r, err;

	msg.server_fd = data->server_fd;

	msg.level = level;
	msg.optname = optname;
	msg.optval = optval;
	msg.optlen = optlen;

	desc = rpc_begin(RPC_FAF_SETSOCKOPT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	err = pack_context(desc);
	if (err)
		goto err_cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto err_cancel;
	err = rpc_unpack_type(desc, r);
	if (err)
		goto err_cancel;

out_end:
	rpc_end(desc, 0);

out:
	return r;

err_cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -ENOMEM;
	r = err;
	goto out_end;
}

long krg_faf_getsockopt (struct file * file,
			 int level,
			 int optname,
			 char __user *optval,
			 int __user *optlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_getsockopt_msg msg;
	int r, err;
	struct rpc_desc *desc;

	msg.server_fd = data->server_fd;

	msg.level = level;
	msg.optname = optname;
	msg.optval = optval;
	msg.optlen = optlen;

	desc = rpc_begin(RPC_FAF_GETSOCKOPT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	err = pack_context(desc);
	if (err)
		goto err_cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto err_cancel;
	err = rpc_unpack_type(desc, r);
	if (err)
		goto err_cancel;

out_end:
	rpc_end(desc, 0);

out:
	return r;

err_cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -ENOMEM;
	r = err;
	goto out_end;
}

ssize_t krg_faf_sendmsg(struct file *file, struct msghdr *msghdr,
			size_t total_len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_sendmsg_msg msg;
	ssize_t r;
	int err;
	struct rpc_desc* desc;

	msg.server_fd = data->server_fd;
	msg.total_len = total_len;
	msg.flags = msghdr->msg_flags;

	desc = rpc_begin(RPC_FAF_SENDMSG, data->server_id);
	if (!desc)
		return -ENOMEM;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = send_msghdr(desc, msghdr, total_len, MSG_USER);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;
	if (r == -EPIPE && !(msghdr->msg_flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);

out_end:
	rpc_end(desc, 0);

	return r;

cancel:
	rpc_cancel(desc);
	r = err;
	goto out_end;
}

ssize_t krg_faf_recvmsg(struct file *file, struct msghdr *msghdr,
			size_t total_len, unsigned int flags)
{
	faf_client_data_t *data = file->private_data;
	struct faf_sendmsg_msg msg;
	ssize_t r;
	int err;
	struct rpc_desc* desc;

	msg.server_fd = data->server_fd;
	msg.total_len = total_len;
	msg.flags = flags;

	desc = rpc_begin(RPC_FAF_RECVMSG, data->server_id);
	if (!desc)
		return -ENOMEM;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = send_msghdr(desc, msghdr, total_len, MSG_USER|MSG_HDR_ONLY);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;

	if (r < 0)
		goto out_end;

	/* Careful, caller may have set MSG_TRUNC */
	err = recv_msghdr(desc, msghdr, min_t(size_t, r, total_len), MSG_USER);
	if (err)
		goto cancel;

	/* Behave as sock_recvmsg() */
	msghdr->msg_control += msghdr->msg_controllen;

out_end:
	rpc_end(desc, 0);

	return r;

cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -EPIPE;
	r = err;
	goto out_end;
}

static ssize_t fwd_sendfile(faf_client_data_t *out, faf_client_data_t *in,
			    loff_t *ppos, size_t count, loff_t max)
{
	struct rpc_desc *desc;
	struct faf_sendfile_msg msg;
	ssize_t retval;
	int err;

	desc = rpc_begin(RPC_FAF_SENDFILE, in->server_id);
	if (!desc) {
		retval = -ENOMEM;
		goto out;
	}

	msg.out_fd = out->server_fd;
	msg.in_fd = in->server_fd;
	msg.ppos = *ppos;
	msg.count = count;
	msg.max = max;

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, *ppos);
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, retval);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return retval;

cancel:
	rpc_cancel(desc);
	retval = err;
	goto out_end;
}

ssize_t krg_faf_sendfile(struct file *out, struct file *in, loff_t *ppos,
			 size_t count, loff_t max)
{
	faf_client_data_t *out_data, *in_data;
	char *buf;
	mm_segment_t oldfs;
	loff_t outpos;
	size_t len;
	ssize_t size, total_size, retval;

	if (out->f_flags & O_FAF_CLT)
		out_data = out->private_data;
	else
		out_data = NULL;

	if (in->f_flags & O_FAF_CLT)
		in_data = in->private_data;
	else
		in_data = NULL;

	BUG_ON(!out_data && !in_data);

	if (in_data && out_data
	    && in_data->server_id == out_data->server_id)
		return fwd_sendfile(out_data, in_data, ppos, count, max);

	len = count;
	if (count > PAGE_SIZE)
		len = PAGE_SIZE;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		goto out;
	}

	total_size = 0;

	while (count != 0) {
		size = vfs_read(in, buf, len, ppos);
		if (size < 0) {
			retval = size;
			goto reset_fs;
		}

		outpos = file_pos_read(out);
		retval = vfs_write(out, buf, size, &outpos);
		if (retval < 0)
			goto reset_fs;

		total_size += size;
		count -= size;
		len = count;
		if (count > PAGE_SIZE)
			len = PAGE_SIZE;
	}

	retval = total_size;

reset_fs:
	set_fs(oldfs);
	kfree(buf);
out:
	return retval;
}

int krg_faf_utimes(struct file *file, struct timespec *times, int flags)
{
	faf_client_data_t *data = file->private_data;
	struct faf_utimes_msg msg;
	struct rpc_desc *desc;
	int err, ret;

	msg.server_fd = data->server_fd;
	msg.flags = flags;
	if (times) {
		msg.times_not_null = true;
		msg.times[0] = times[0];
		msg.times[1] = times[1];
	} else
		msg.times_not_null = false;

	desc = rpc_begin(RPC_FAF_UTIMES, data->server_id);
	if (!desc) {
		ret = -ENOMEM;
		goto out;
	}

	err = rpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = rpc_unpack_type(desc, ret);
	if (err)
		goto cancel;

out_end:
	rpc_end(desc, 0);
out:
	return ret;

cancel:
	ret = err;
	if (ret == -ECANCELED)
		ret = -EPIPE;
	rpc_cancel(desc);
	goto out_end;
}

void krg_faf_srv_close(struct file *file)
{
	check_close_faf_srv_file(file);
}

int krg_faf_poll_wait(struct file *file, int wait)
{
	faf_client_data_t *data = file->private_data;
	struct faf_poll_wait_msg msg;
	struct rpc_desc *desc;
	unsigned int revents;
	int err = -ENOMEM, res = 0;
	long old_state = current->state;

	data->poll_revents = 0;

	msg.server_fd = data->server_fd;
	msg.objid = file->f_objid;
	msg.wait = wait;

	desc = rpc_begin(RPC_FAF_POLL_WAIT, data->server_id);
	if (!desc)
		goto out;
	err = rpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	if (wait) {
		err = rpc_unpack_type(desc, res);
		if (err)
			goto err_cancel;
	}
	err = rpc_unpack_type(desc, revents);
	if (err)
		goto err_cancel;

	if (res)
		err = res;
	data->poll_revents = revents;

out_end:
	rpc_end(desc, 0);

out:
	/*
	 * after sleeping rpc_unpack() returns with
	 * current->state == TASK_RUNNING
	 */
	set_current_state(old_state);
	return err;

err_cancel:
	rpc_cancel(desc);
	if (err == -ECANCELED)
		err = -ENOMEM;
	goto out_end;
}

void krg_faf_poll_dequeue(struct file *file)
{
	faf_client_data_t *data = file->private_data;
	struct faf_notify_msg msg;
	int err;

	msg.server_fd = data->server_fd;
	msg.objid = file->f_objid;
	err = rpc_async(RPC_FAF_POLL_DEQUEUE, data->server_id,
			&msg, sizeof(msg));
	if (err)
		printk("faf_poll: memory leak on server %d!\n", data->server_id);
}

/** Kerrighed kernel hook for FAF poll function.
 *  @author Renaud Lottiaux
 *
 *  @param file          File to do a poll to.
 */
unsigned int faf_poll (struct file *file,
		       struct poll_table_struct *wait)
{
	faf_client_data_t *data = file->private_data;
	unsigned int revents;
	long old_state = current->state;

	mutex_lock(&faf_poll_mutex);
	/* Waking up from mutex_lock() sets current->state to TASK_RUNNING */
	set_current_state(old_state);
	poll_wait(file, &data->poll_wq, wait);
	if (!wait)
		krg_faf_poll_wait(file, 0);
	revents = data->poll_revents;
	mutex_unlock(&faf_poll_mutex);

	return revents;
}

static void handle_faf_poll_notify(struct rpc_desc *desc,
				   void *_msg,
				   size_t size)
{
	unsigned long dvfs_id = *(unsigned long *)_msg;
	struct file *file;
	faf_client_data_t *data;

	file = lock_dvfs_file(dvfs_id);
	if (file) {
		data = file->private_data;
		wake_up_interruptible_all(&data->poll_wq);
	}
	unlock_dvfs_file(dvfs_id);
}

struct file_operations faf_file_ops = {
	poll: faf_poll,
};



/* FAF Hooks Initialisation */

void faf_hooks_init (void)
{
	rpc_register_void(RPC_FAF_POLL_NOTIFY, handle_faf_poll_notify, 0);
}

/* FAF Hooks Finalization */
void faf_hooks_finalize (void)
{
}
