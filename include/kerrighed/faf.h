/** Kerrighed Kernel Hooks **/

#ifndef __FAF_H__
#define __FAF_H__

#include <linux/types.h>
#include <linux/namei.h>

struct file;
struct iovec;
struct kstat;
struct statfs;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

typedef struct faf_client_data {
	kerrighed_node_t server_id;
	int server_fd;
	unsigned long f_flags;
	fmode_t f_mode;
	loff_t f_pos;
	wait_queue_head_t poll_wq;
	unsigned int poll_revents;
	umode_t i_mode;
	unsigned int is_named_pipe:1;
} faf_client_data_t;

off_t krg_faf_lseek(struct file *file, off_t offset,
		    unsigned int origin);
long krg_faf_llseek(struct file *file, unsigned long offset_high,
		    unsigned long offset_low, loff_t *result,
		    unsigned int origin);
ssize_t krg_faf_read(struct file *file, char *buf, size_t count, loff_t *pos);
ssize_t krg_faf_write(struct file *file, const char *buf,
		      size_t count, loff_t *pos);
ssize_t krg_faf_readv(struct file *file, const struct iovec __user *vec,
		      unsigned long vlen, loff_t *pos);
ssize_t krg_faf_writev(struct file *file, const struct iovec __user *vec,
		       unsigned long vlen, loff_t *pos);

enum getdents_filler {
	OLDREADDIR,
	GETDENTS,
	GETDENTS64
};

int krg_faf_getdents(struct file *file, enum getdents_filler filler,
		     void *dirent, unsigned int count);
long krg_faf_fcntl(struct file *file, unsigned int cmd,
		   unsigned long arg);
long krg_faf_fcntl64(struct file *file, unsigned int cmd,
		     unsigned long arg);
long krg_faf_ioctl(struct file *file, unsigned int cmd,
		   unsigned long arg);
long krg_faf_fstat(struct file *file, struct kstat *stat);
long krg_faf_fstatfs(struct file *file, struct statfs *statfs);
long krg_faf_fsync(struct file *file);
long krg_faf_ftruncate(struct file *file, loff_t length, int small);
long krg_faf_flock(struct file *file, unsigned int cmd);
int krg_faf_fchmod(struct file *file, mode_t mode);
int krg_faf_fchown(struct file *file, uid_t user, gid_t group);
long krg_faf_fallocate(struct file *file, int mode, loff_t offset, loff_t len);

struct timespec;
int krg_faf_utimes(struct file *file, struct timespec *times, int flags);

int krg_faf_fremovexattr(struct file *file, const char __user *name);

char *krg_faf_d_path(const struct file *file, char *buffer, int size, bool *deleted);
char *krg_faf_phys_d_path(const struct file *file, char *buff, int size, bool *deleted);
int krg_faf_do_path_lookup(struct file *file, const char *name,
			   unsigned int flags, struct nameidata *nd);
void krg_faf_srv_close(struct file *file);

struct sockaddr;
struct msghdr;

long krg_faf_bind(struct file *file, struct sockaddr __user *umyaddr,
		  int addrlen);
long krg_faf_connect(struct file *file,
		     struct sockaddr __user *uservaddr, int addrlen);
long krg_faf_listen(struct file *file, int backlog);
long krg_faf_accept(struct file *file,
		    struct sockaddr __user *upeer_sockaddr,
		    int __user *upeer_addrlen);
long krg_faf_getsockname(struct file *file,
			 struct sockaddr __user *usockaddr,
			 int __user *usockaddr_len);
long krg_faf_getpeername(struct file *file,
			 struct sockaddr __user *usockaddr,
			 int __user *usockaddr_len);
long krg_faf_shutdown(struct file *file, int how);
long krg_faf_setsockopt(struct file *file, int level, int optname,
			char __user *optval, int optlen);
long krg_faf_getsockopt(struct file *file, int level, int optname,
			char __user *optval, int __user *optlen);
ssize_t krg_faf_sendmsg(struct file *file, struct msghdr *msg,
			size_t total_len);
ssize_t krg_faf_recvmsg(struct file *file, struct msghdr *msg,
			size_t total_len, unsigned int flags);
ssize_t krg_faf_sendfile(struct file *out, struct file *in, loff_t *ppos,
			 size_t count, loff_t max);
int krg_faf_poll_wait(struct file *file, int wait);
void krg_faf_poll_dequeue(struct file *file);

/* Remote user access */
unsigned long krg_copy_user_generic(void *to, const void *from,
				    unsigned long n, int zerorest);
long krg___strncpy_from_user(char *dst, const char __user *src,
			     unsigned long count);
unsigned long krg___strnlen_user(const char __user *str,
					  unsigned long n);
unsigned long krg___clear_user(void __user *mem, unsigned long len);

/* functions used by other subsystems */
int setup_faf_file_if_needed(struct file *file);

int setup_faf_file(struct file *file);

#endif // __FAF_H__
