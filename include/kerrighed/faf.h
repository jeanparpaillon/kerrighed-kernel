/** Kerrighed Kernel Hooks **/

#ifndef __FAF_H__
#define __FAF_H__

#include <linux/types.h>

struct file;
struct kstat;

off_t krg_faf_lseek(struct file *file, off_t offset,
		    unsigned int origin);
long krg_faf_llseek(struct file *file, unsigned long offset_high,
		    unsigned long offset_low, loff_t *result,
		    unsigned int origin);
ssize_t krg_faf_read(struct file *file, char *buf, size_t count);
ssize_t krg_faf_write(struct file *file, const char *buf,
		      size_t count);
long krg_faf_fcntl(struct file *file, unsigned int cmd,
		   unsigned long arg);
long krg_faf_fcntl64(struct file *file, unsigned int cmd,
		     unsigned long arg);
long krg_faf_ioctl(struct file *file, unsigned int cmd,
		   unsigned long arg);
long krg_faf_fstat(struct file *file, struct kstat *stat);
long krg_faf_fsync(struct file *file);
long krg_faf_flock(struct file *file, unsigned int cmd);
char *krg_faf_d_path(struct file *file, char *buffer, int size);
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
long krg_faf_send(struct file *file, void __user *buff, size_t len,
		  unsigned flags);
long krg_faf_sendto(struct file *file, void __user *buff,
		    size_t len, unsigned flags,
		    struct sockaddr __user *addr, int addr_len);
long krg_faf_recv(struct file *file, void __user *ubuf, size_t size,
		  unsigned flags);
long krg_faf_recvfrom(struct file *file, void __user *ubuf,
		      size_t size, unsigned flags,
		      struct sockaddr __user *addr,
		      int __user *addr_len);
long krg_faf_shutdown(struct file *file, int how);
long krg_faf_setsockopt(struct file *file, int level, int optname,
			char __user *optval, int optlen);
long krg_faf_getsockopt(struct file *file, int level, int optname,
			char __user *optval, int __user *optlen);
long krg_faf_sendmsg(struct file *file, struct msghdr __user *msg,
		     unsigned flags);
long krg_faf_recvmsg(struct file *file, struct msghdr __user *msg,
		     unsigned int flags);
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

#endif // __FAF_H__
