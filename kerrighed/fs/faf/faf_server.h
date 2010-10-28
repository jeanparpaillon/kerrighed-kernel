/** Kerrighed FAF Server.
 *  @file faf_server.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __FAF_SERVER__
#define __FAF_SERVER__

#include <linux/socket.h>
#include <linux/time.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct faf_rw_msg {
	int server_fd;
	size_t count;
	loff_t pos;
};

struct faf_rw_ret {
	ssize_t ret;
	loff_t pos;
};

enum getdents_filler;

struct faf_getdents_msg {
	int server_fd;
	enum getdents_filler filler;
	int count;
};

struct faf_d_path_msg {
	int server_fd;
	int deleted;
	size_t count;
};

struct faf_notify_msg {
	int server_fd;
	unsigned long objid;
};

struct faf_stat_msg {
	int server_fd;
	long flags;
};

struct faf_statfs_msg {
	int server_fd;
};

struct faf_ctl_msg {
	int server_fd;
	unsigned int cmd;
	union {
		unsigned long arg;
		struct flock flock;
#if BITS_PER_LONG == 32
		struct flock64 flock64;
#endif
	};
};

struct faf_seek_msg {
	int server_fd;
	off_t offset;
	unsigned int origin;
};

struct faf_llseek_msg {
	int server_fd;
	unsigned long offset_high;
	unsigned long offset_low;
	unsigned int origin;
};

struct faf_truncate_msg {
	int server_fd;
	loff_t length;
	int small;
};

struct faf_chmod_msg {
	int server_fd;
	mode_t mode;
};

struct faf_chown_msg {
	int server_fd;
	uid_t user;
	gid_t group;
};

struct faf_allocate_msg {
	int server_fd;
	int mode;
	loff_t offset;
	loff_t len;
};

struct faf_listxattr_msg {
	int server_fd;
	size_t size;
};

struct faf_removexattr_msg {
	int server_fd;
	size_t name_len;
};

struct faf_bind_msg {
	int server_fd;
	int addrlen;
	struct sockaddr_storage sa;
};

struct faf_listen_msg {
	int server_fd;
	int sub_chan;
	int backlog;
};

struct faf_shutdown_msg {
	int server_fd;
	int how;
};

struct faf_setsockopt_msg {
	int server_fd;
	int level;
	int optname;
	char __user *optval;
	int optlen;
};

struct faf_getsockopt_msg {
	int server_fd;
	int level;
	int optname;
	char __user *optval;
	int __user *optlen;
};

struct faf_sendmsg_msg {
	int server_fd;
	unsigned int flags;
	size_t total_len;
};

struct faf_sendfile_msg {
	int out_fd;
	int in_fd;
	loff_t ppos;
	size_t count;
	loff_t max;
};

struct faf_poll_wait_msg {
	int server_fd;
	unsigned long objid;
	int wait;
};

struct faf_utimes_msg {
	int server_fd;
	int flags;
	bool times_not_null;
	struct timespec times[2];
};

struct old_linux_dirent;
extern int do_oldreaddir(struct file *file, struct old_linux_dirent *dirent,
			 unsigned int count);

struct linux_dirent;
extern int do_getdents(struct file *file, struct linux_dirent *dirent,
		       unsigned int count);

struct linux_dirent64;
extern int do_getdents64(struct file *file, struct linux_dirent64 *dirent,
			 unsigned int count);

extern ssize_t do_sendfile(int out_fd, int in_fd, loff_t *ppos,
			   size_t count, loff_t max);

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

void faf_server_init (void);
void faf_server_finalize (void);

#endif // __FAF_SERVER__
