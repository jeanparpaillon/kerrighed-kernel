/** Kerrighed FAF servers.
 *  @file faf_server.c
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/fs.h>
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


/** Handler for reading in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_read (struct rpc_desc* desc,
		      void *msgIn, size_t size)
{
	struct faf_rw_msg *msg = msgIn;
	char *buf = NULL;
	long buf_size = PAGE_SIZE;
	ssize_t to_read, r;

	r = remote_sleep_prepare(desc);
	if (r) {
		rpc_cancel(desc);
		return;
	}

	r = -ENOMEM;
	buf = kmalloc (PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL)
		goto exit;

	to_read = msg->count;
	while (to_read > 0) {
		if (to_read < PAGE_SIZE)
			buf_size = to_read;

		r = sys_read (msg->server_fd, buf, buf_size);

		if (r > 0) {
			rpc_pack_type(desc, r);
			rpc_pack(desc, 0, buf, r);
		}

		/* Check if we have reach the end of the file */
		if (r < buf_size)
			break;
		to_read -= r;
	}
	/* Pack the end of transmission mark (0) */
	if (r > 0)
		r = 0;
	/* else, pack the error value */
exit:
	rpc_pack_type(desc, r);
	if (buf)
		kfree (buf);

	remote_sleep_finish();
}

/** Handler for writing in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_write (struct rpc_desc* desc,
		       void *msgIn, size_t size)
{
	struct faf_rw_msg *msg = msgIn;
	long to_recv;
	char *buf = NULL;
	ssize_t buf_size = PAGE_SIZE;
	ssize_t r, nr_received = -ENOMEM;

	r = remote_sleep_prepare(desc);
	if (r) {
		rpc_cancel(desc);
		return;
	}

	buf = kmalloc (PAGE_SIZE, GFP_KERNEL);
	if (buf == NULL)
		goto err;

	nr_received = 0;
	to_recv = msg->count;
	while (to_recv > 0) {
		if (to_recv < PAGE_SIZE)
			buf_size = to_recv;
		if(rpc_unpack(desc, 0, buf, to_recv) == RPC_ECLOSE) {
			nr_received = -EPIPE;
			goto err;
		}

		r = sys_write (msg->server_fd, buf, buf_size);

		/* The last write failed. Break the write sequence */
		if (r < 0) {
			nr_received = r;
			goto err;
		}
		nr_received += r;
		to_recv -= buf_size;
	}
err:
	rpc_pack_type(desc, nr_received);
	if (nr_received < 0)
		rpc_cancel(desc);
	if (buf)
		kfree (buf);

	remote_sleep_finish();

	return;
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
	long r;
	int err;

	err = prepare_ruaccess(desc);
	if (err)
		goto out_err;
	r = sys_ioctl (msg->server_fd, msg->cmd, msg->arg);
	err = cleanup_ruaccess(desc);
	if (err)
		goto out_err;

	err = rpc_pack_type(desc, r);
	if (err)
		goto out_err;
	return;

out_err:
	rpc_cancel(desc);
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
	unsigned long arg;
	long r;
	int err;

	if (msg->cmd == F_GETLK || msg->cmd == F_SETLK || msg->cmd == F_SETLKW)
		arg = (unsigned long) &msg->flock;
	else
		arg = msg->arg;

	r = sys_fcntl (msg->server_fd, msg->cmd, arg);

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
	unsigned long arg;
	long r;
	int err;

	if (msg->cmd == F_GETLK64 || msg->cmd == F_SETLK64 || msg->cmd == F_SETLKW64)
		arg = (unsigned long) &msg->flock64;
	else
		arg = msg->arg;

	r = sys_fcntl64 (msg->server_fd, msg->cmd, arg);

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

	r = vfs_fstat (msg->server_fd, &statbuf);

	rpc_pack_type(desc, r);
	rpc_pack_type(desc, statbuf);
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
void handle_faf_lseek (struct rpc_desc* desc,
		       void *msgIn, size_t size)
{
	struct faf_seek_msg *msg = msgIn;
	off_t r = -EINVAL;

	r = sys_lseek (msg->server_fd, msg->offset, msg->origin);

	rpc_pack_type(desc, r);
}

/** Handler for seeking in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
void handle_faf_llseek (struct rpc_desc* desc,
			void *msgIn, size_t size)
{
	struct faf_llseek_msg *msg = msgIn;
	long r = -EINVAL;
	loff_t result;

	r = sys_llseek (msg->server_fd, msg->offset_high, msg->offset_low,
			&result, msg->origin);

	rpc_pack_type(desc, r);
	rpc_pack_type(desc, result);
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

/** Handler for locking in a FAF open file.
 *  @author Renaud Lottiaux
 *
 *  @param from    Node sending the request
 *  @param msgIn   Request message
 */
int handle_faf_flock (struct rpc_desc* desc,
                      void *msgIn, size_t size)
{
	struct faf_ctl_msg *msg = msgIn;
	long r = -EINVAL;

	r = sys_flock (msg->server_fd, msg->cmd);

	return r;
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
	struct dvfs_file_struct *dvfs_file;
	struct faf_polled_fd *polled_fd;
	struct faf_polled_fd_node *polled_fd_node;
	struct hlist_node *pos;

	dvfs_file = _kddm_get_object_no_ft(dvfs_file_struct_ctnr, dvfs_id);
	if (dvfs_file && dvfs_file->file) {
		/* TODO: still required? */
		if (atomic_read (&dvfs_file->file->f_count) == 0)
			dvfs_file->file = NULL;
	}
	if (!dvfs_file || !dvfs_file->file)
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
	_kddm_put_object(dvfs_file_struct_ctnr, dvfs_id);
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
	struct dvfs_file_struct *dvfs_file;
	struct faf_polled_fd *polled_fd;
	struct faf_polled_fd_node *polled_fd_node;
	int err;

	dvfs_file = _kddm_get_object_no_ft(dvfs_file_struct_ctnr, dvfs_id);
	if (dvfs_file && dvfs_file->file) {
		/* TODO: still required? */
		if (atomic_read (&dvfs_file->file->f_count) == 0)
			dvfs_file->file = NULL;
	}

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

	if (!dvfs_file || !dvfs_file->file)
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

	_kddm_put_object(dvfs_file_struct_ctnr, dvfs_id);

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
	struct faf_rw_msg *msg = msgIn;
	char *buff, *file_name = NULL;
	struct file *file;
	int len;
	int err;

	buff = kmalloc (msg->count, GFP_KERNEL);

	file = fcheck_files (current->files, msg->server_fd);
	/* Remote caller holds a reference so it can't disappear. */
	BUG_ON(!file);
	file_name = d_path(&file->f_path, buff, msg->count);
	if (IS_ERR(file_name))
		len = PTR_ERR(file_name);
	else
		len = strlen(file_name) + 1;

	err = rpc_pack_type(desc, len);
	if (err)
		goto err_cancel;
	if (len >= 0)
		err = rpc_pack(desc, 0, file_name, len);
	if (err)
		goto err_cancel;

out:
	kfree (buff);

	return;

err_cancel:
	rpc_cancel(desc);
	goto out;
}



int handle_faf_bind (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	int r;

	r = sys_bind(msg->server_fd, (struct sockaddr *)&msg->sa, msg->addrlen);

	return r;
}

int handle_faf_connect (struct rpc_desc* desc,
			void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	int r;

	r = sys_connect(msg->server_fd,
			(struct sockaddr *)&msg->sa, msg->addrlen);

	return r;
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
	int r;
	struct file *file;
	void *fdesc;
	int desc_len;

	r = sys_accept(msg->server_fd,
		       (struct sockaddr *)&msg->sa, &msg->addrlen);

	rpc_pack_type(desc, r);
	if (r < 0)
		return;

	file = fcheck_files(current->files, r);

	if (!file->f_objid)
		create_kddm_file_object(file);

	file->f_flags |= O_FAF_SRV;
	file->f_faf_srv_index = r;

	/* Increment the DVFS count for the client node */
	get_dvfs_file(r, file->f_objid);

	get_faf_file_krg_desc(file, &fdesc, &desc_len);

	rpc_pack_type(desc, desc_len);
	rpc_pack(desc, 0, fdesc, desc_len);
	kfree(fdesc);

	rpc_pack_type(desc, msg->addrlen);
	rpc_pack(desc, 0, &msg->sa, msg->addrlen);
	rpc_pack_type(desc, file->f_objid);

	if (rpc_unpack_type(desc, r)) {
		/* The client couldn't setup a FAF client file. */
		put_dvfs_file(file->f_faf_srv_index, file);
		check_close_faf_srv_file(file);
		r = -ENOMEM;
	}
}

int handle_faf_getsockname (struct rpc_desc* desc,
			    void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	int r;

	r = sys_getsockname(msg->server_fd,
			    (struct sockaddr *)&msg->sa, &msg->addrlen);

	rpc_pack_type(desc, msg->addrlen);
	rpc_pack(desc, 0, &msg->sa, msg->addrlen);

	return r;
}

int handle_faf_getpeername (struct rpc_desc* desc,
			    void *msgIn, size_t size)
{
	struct faf_bind_msg *msg = msgIn;
	int r;

	r = sys_getpeername(msg->server_fd,
			    (struct sockaddr *)&msg->sa, &msg->addrlen);

	rpc_pack_type(desc, msg->addrlen);
	rpc_pack(desc, 0, &msg->sa, msg->addrlen);

	return r;
}

int handle_faf_send (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_send_msg *msg = msgIn;
	int r = -ENOMEM;
	void *buff;

	buff = vmalloc(msg->len);
	if (buff) {
		rpc_unpack(desc, 0, buff, msg->len);
		r = sys_send(msg->server_fd, buff, msg->len, msg->flags);
		vfree(buff);
	}

	return r;
}

int handle_faf_sendto (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_sendto_msg *msg = msgIn;
	int r = -ENOMEM;
	void *buff;

	buff = vmalloc(msg->len);

	if (buff) {
		rpc_unpack(desc, 0, buff, msg->len);
		r = sys_sendto(msg->server_fd, buff, msg->len, msg->flags,
			       (struct sockaddr *)&msg->sa, msg->addrlen);
		vfree(buff);
	}

	return r;
}

int handle_faf_recv (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_send_msg *msg = msgIn;
	int r = -ENOMEM;
	void *buff;

	buff = vmalloc(msg->len);
	if (!buff)
		goto exit;

	r = sys_recv(msg->server_fd, buff, msg->len, msg->flags);

	if (r > 0)
		rpc_pack(desc, 0, buff, r);

	vfree(buff);
exit:
	return r;
}

int handle_faf_recvfrom (struct rpc_desc* desc,
                     void *msgIn, size_t size)
{
	struct faf_sendto_msg *msg = msgIn;
	int r = -ENOMEM;
	void *buff;

	buff = vmalloc(msg->len);
	if (!buff)
		goto exit;

	r = sys_recvfrom(msg->server_fd, buff, msg->len, msg->flags,
			 (struct sockaddr *)&msg->sa, &msg->addrlen);

	if (r > 0)
		rpc_pack(desc, 0, buff, r);

	if (r >= 0) {
		rpc_pack_type(desc, msg->addrlen);
		rpc_pack(desc, 0, &msg->sa, msg->addrlen);
	}

	vfree(buff);
exit:
	return r;
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
	int r, err;

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
	int r, err;

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
	return;

out_err:
	rpc_cancel(desc);
	if (err > 0)
		err = -ENOMEM;
	r = err;
	goto exit;
}

int handle_faf_sendmsg (struct rpc_desc* desc,
			void *msgIn, size_t size)
{
	struct faf_sendmsg_msg *msg = msgIn;
	int r;
	struct msghdr msghdr;

	memset(&msghdr, 0, sizeof(msghdr));

	recv_msghdr(desc, &msghdr, 0);

	r = sys_sendmsg (msg->server_fd, &msghdr, msg->flags);

	free_msghdr(&msghdr);

	return r;
}

int handle_faf_recvmsg (struct rpc_desc* desc,
			void *msgIn, size_t size)
{
	struct faf_sendmsg_msg *msg = msgIn;
	int r;
	struct msghdr msghdr;

	memset(&msghdr, 0, sizeof(msghdr));

	recv_msghdr(desc, &msghdr, 0);

	r = sys_recvmsg(msg->server_fd, &msg->msghdr, msg->flags);

	send_msghdr(desc, &msghdr, 0);

	free_msghdr(&msghdr);

	return r;
}

int handle_faf_notify_close (struct rpc_desc* desc,
			     void *msgIn, size_t size)
{
	struct faf_notify_msg *msg = msgIn;
	struct file *file;

	file = fcheck_files(current->files, msg->server_fd);
	/* Check if the file has been closed locally before we receive the
	 * notification message.
	 */
	if (file == NULL)
		return 0;
	if (file->f_objid != msg->objid)
		return 0;
	BUG_ON (!(file->f_flags & O_FAF_SRV));

	check_close_faf_srv_file(file);

	return 0;
}

/* FAF handler Initialisation */
void faf_server_init (void)
{
	rpc_register_void(RPC_FAF_READ, handle_faf_read, 0);
	rpc_register_void(RPC_FAF_WRITE, handle_faf_write, 0);
	faf_poll_init();
	rpc_register_void(RPC_FAF_IOCTL, handle_faf_ioctl, 0);
	rpc_register_void(RPC_FAF_FCNTL, handle_faf_fcntl, 0);

#if BITS_PER_LONG == 32
	rpc_register_void(RPC_FAF_FCNTL64, handle_faf_fcntl64, 0);
#endif

	rpc_register_void(RPC_FAF_FSTAT, handle_faf_fstat, 0);
	rpc_register_void(RPC_FAF_FSTATFS, handle_faf_fstatfs, 0);
	rpc_register_int(RPC_FAF_FSYNC, handle_faf_fsync, 0);
	rpc_register_int(RPC_FAF_FLOCK, handle_faf_flock, 0);
	rpc_register_void(RPC_FAF_LSEEK, handle_faf_lseek, 0);
	rpc_register_void(RPC_FAF_LLSEEK, handle_faf_llseek, 0);
	rpc_register_void(RPC_FAF_D_PATH, handle_faf_d_path, 0);

	rpc_register_int(RPC_FAF_BIND, handle_faf_bind, 0);
	rpc_register_int(RPC_FAF_CONNECT, handle_faf_connect, 0);
	rpc_register_int(RPC_FAF_LISTEN, handle_faf_listen, 0);
	rpc_register_void(RPC_FAF_ACCEPT, handle_faf_accept, 0);
	rpc_register_int(RPC_FAF_GETSOCKNAME, handle_faf_getsockname, 0);
	rpc_register_int(RPC_FAF_GETPEERNAME, handle_faf_getpeername, 0);
	rpc_register_int(RPC_FAF_SEND, handle_faf_send, 0);
	rpc_register_int(RPC_FAF_SENDTO, handle_faf_sendto, 0);
	rpc_register_int(RPC_FAF_RECV, handle_faf_recv, 0);
	rpc_register_int(RPC_FAF_RECVFROM, handle_faf_recvfrom, 0);
	rpc_register_int(RPC_FAF_SHUTDOWN, handle_faf_shutdown, 0);
	rpc_register_void(RPC_FAF_SETSOCKOPT, handle_faf_setsockopt, 0);
	rpc_register_void(RPC_FAF_GETSOCKOPT, handle_faf_getsockopt, 0);
	rpc_register_int(RPC_FAF_SENDMSG, handle_faf_sendmsg, 0);
	rpc_register_int(RPC_FAF_RECVMSG, handle_faf_recvmsg, 0);
	rpc_register_int(RPC_FAF_NOTIFY_CLOSE, handle_faf_notify_close, 0);
}

/* FAF server Finalization */
void faf_server_finalize (void)
{
}
