/*
 * DONEVFS:	faf support is implemented at VFS level
 * DONESYS:	faf support is implemented at syscall level
 * DONELKP:	faf support is implemented thanks to user_path_at,
 *					user_path_parent, or lookup
 * DONENO:	there is nothing to do :-)
 *
 * INCOMPLETE:	faf support is incomplete
 * STODO:	faf is not yet supported but it is quite easy to implement it
 * TODO:	faf is not yet supported
 */

/* fsync and fdatasync are using vfs_fsync */
DONEVFS long sys_fsync(unsigned int fd);
DONEVFS long sys_fdatasync(unsigned int fd);

DONESYS long sys_ftruncate(unsigned int fd, unsigned long length);
DONESYS long sys_fstatfs(unsigned int fd, struct statfs __user *buf);

/* 32 bits only */
STODO long sys_fstatfs64(unsigned int fd, size_t sz,
				struct statfs64 __user *buf);

/* fstat, newstat, fstat64 are using vfs_stat */
DONEVFS long sys_fstat(unsigned int fd,
		       struct __old_kernel_stat __user *statbuf);
DONEVFS long sys_newfstat(unsigned int fd, struct stat __user *statbuf);

#if BITS_PER_LONG == 32
DONEVFS long sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);

/* 32 bits only */
DONESYS long sys_ftruncate64(unsigned int fd, loff_t length);
#endif


DONESYS long sys_fsetxattr(int fd, const char __user *name,
			      const void __user *value, size_t size, int flags);
DONESYS long sys_fgetxattr(int fd, const char __user *name,
			      void __user *value, size_t size);
DONESYS long sys_flistxattr(int fd, char __user *list, size_t size);
DONESYS long sys_fremovexattr(int fd, const char __user *name);

/* need mapping support */
TODO long sys_fadvise64(int fd, loff_t offset, size_t len, int advice);
TODO long sys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice);

DONESYS long sys_fchmod(unsigned int fd, mode_t mode);

DONESYS long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
#if BITS_PER_LONG == 32
/* 32 bits only */
DONESYS long sys_fcntl64(unsigned int fd,
			 unsigned int cmd, unsigned long arg);
#endif

DONENO long sys_dup(unsigned int fildes);
DONENO long sys_dup2(unsigned int oldfd, unsigned int newfd);
DONENO long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
DONESYS long sys_ioctl(unsigned int fd, unsigned int cmd,
				unsigned long arg);
DONESYS long sys_flock(unsigned int fd, unsigned int cmd);

/* sendfile and sendfile64 are using do_sendfile */
DONESYS long sys_sendfile(int out_fd, int in_fd,
			     off_t __user *offset, size_t count);
DONESYS long sys_sendfile64(int out_fd, int in_fd,
			       loff_t __user *offset, size_t count);

DONENO long sys_close(unsigned int fd);
DONESYS long sys_fchown(unsigned int fd, uid_t user, gid_t group);

#ifdef CONFIG_UID16
/* fchown16 calls fchown() */
DONESYS long sys_fchown16(unsigned int fd, old_uid_t user, old_gid_t group);
#endif

/* lseek and llseek implements faf support but vfs_lseek does it too !! */
DONESYS long sys_lseek(unsigned int fd, off_t offset,
			  unsigned int origin);
DONESYS long sys_llseek(unsigned int fd, unsigned long offset_high,
			unsigned long offset_low, loff_t __user *result,
			unsigned int origin);

DONEVFS long sys_read(unsigned int fd, char __user *buf, size_t count);

/* need mapping support */
TODO long sys_readahead(int fd, loff_t offset, size_t count);

DONEVFS long sys_readv(unsigned long fd,
			  const struct iovec __user *vec,
			  unsigned long vlen);
DONEVFS long sys_write(unsigned int fd, const char __user *buf,
			  size_t count);
DONEVFS long sys_writev(unsigned long fd,
			   const struct iovec __user *vec,
			   unsigned long vlen);
DONEVFS long sys_pread64(unsigned int fd, char __user *buf,
			    size_t count, loff_t pos);
DONEVFS long sys_pwrite64(unsigned int fd, const char __user *buf,
			     size_t count, loff_t pos);
DONEVFS long sys_preadv(unsigned long fd, const struct iovec __user *vec,
			   unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
DONEVFS long sys_pwritev(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h);

/* lookup locally with remote path of faffed directory can not work*/
TODO long sys_fchdir(unsigned int fd);

DONESYS long sys_getdents(unsigned int fd,
				struct linux_dirent __user *dirent,
				unsigned int count);
DONESYS long sys_getdents64(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count);

DONESYS long sys_setsockopt(int fd, int level, int optname,
				char __user *optval, int optlen);
DONESYS long sys_getsockopt(int fd, int level, int optname,
				char __user *optval, int __user *optlen);
DONESYS long sys_bind(int, struct sockaddr __user *, int);
DONESYS long sys_connect(int, struct sockaddr __user *, int);

/* accept() is calling accept4() */
DONESYS long sys_accept(int, struct sockaddr __user *, int __user *);
DONESYS long sys_accept4(int, struct sockaddr __user *, int __user *, int);

DONESYS long sys_getsockname(int, struct sockaddr __user *, int __user *);
DONESYS long sys_getpeername(int, struct sockaddr __user *, int __user *);

/* send() is calling sendto() */
DONESYS long sys_send(int, void __user *, size_t, unsigned);
DONESYS long sys_sendto(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int);

DONESYS long sys_sendmsg(int fd, struct msghdr __user *msg, unsigned flags);

/* recv() is calling recvfrom() */
DONESYS long sys_recv(int, void __user *, size_t, unsigned);
DONESYS long sys_recvfrom(int, void __user *, size_t, unsigned,
				struct sockaddr __user *, int __user *);
DONESYS long sys_recvmsg(int fd, struct msghdr __user *msg, unsigned flags);
DONESYS long sys_listen(int, int);
DONESYS long sys_poll(struct pollfd __user *ufds, unsigned int nfds,
				long timeout);
DONESYS long sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			fd_set __user *exp, struct timeval __user *tvp);
TODO long sys_epoll_ctl(int epfd, int op, int fd,
				struct epoll_event __user *event);
TODO long sys_epoll_wait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout);
TODO long sys_epoll_pwait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout,
				const sigset_t __user *sigmask,
				size_t sigsetsize);

/* beware that fsnotify_open is not called from do_sys_open in faf case */
TODO long sys_inotify_add_watch(int fd, const char __user *path,
					u32 mask);
TODO long sys_inotify_rm_watch(int fd, __s32 wd);

/* PowerPC only ?? */
long sys_spu_run(int fd, __u32 __user *unpc,
				 __u32 __user *ustatus);
long sys_spu_create(const char __user *name,
		unsigned int flags, mode_t mode, int fd);


DONELKUP long sys_mknodat(int dfd, const char __user * filename, int mode,
			    unsigned dev);
DONELKUP long sys_mkdirat(int dfd, const char __user * pathname, int mode);
DONELKUP long sys_unlinkat(int dfd, const char __user * pathname, int flag);
DONELKUP long sys_linkat(int olddfd, const char __user *oldname,
			   int newdfd, const char __user *newname, int flags);
DONELKUP long sys_renameat(int olddfd, const char __user * oldname,
			     int newdfd, const char __user * newname);
DONEVFS long sys_futimesat(int dfd, char __user *filename,
			      struct timeval __user *utimes);
DONELKUP long sys_faccessat(int dfd, const char __user *filename, int mode);
DONELKUP long sys_fchmodat(int dfd, const char __user * filename,
			     mode_t mode);
DONELKUP long sys_fchownat(int dfd, const char __user *filename, uid_t user,
			     gid_t group, int flag);
DONELKUP long sys_openat(int dfd, const char __user *filename, int flags,
			   int mode);


/*
 * Missing comment in vfs_fstatat for particular case
 * 	if ((!path.dentry) && (path.mnt)) {
 *
 * Louis thinks it's related to /proc/<pid>/fd/ with faffed files
 * and that it is BUGGY!!!
 */
DONEVFS + DONELKUP long sys_newfstatat(int dfd, char __user *filename,
			       struct stat __user *statbuf, int flag);

DONEVFS + DONELKUP long sys_fstatat64(int dfd, char __user *filename,
			       struct stat64 __user *statbuf, int flag);
/**********************************************************************/

DONELKUP long sys_readlinkat(int dfd, const char __user *path, char __user *buf,
			       int bufsiz);
DONEVFS long sys_utimensat(int dfd, char __user *filename,
				struct timespec __user *utimes, int flags);

TODO long sys_splice(int fd_in, loff_t __user *off_in,
			   int fd_out, loff_t __user *off_out,
			   size_t len, unsigned int flags);

TODO long sys_vmsplice(int fd, const struct iovec __user *iov,
			     unsigned long nr_segs, unsigned int flags);

TODO long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);

/* sys_sync_file_range2 is using sys_sync_file_range */
/* need mapping support */
TODO long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes,
					unsigned int flags);
TODO long sys_sync_file_range2(int fd, unsigned int flags,
				     loff_t offset, loff_t nbytes);


TODO long sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);
TODO long sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);

TODO long sys_timerfd_settime(int ufd, int flags,
				    const struct itimerspec __user *utmr,
				    struct itimerspec __user *otmr);
TODO long sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr);


DONESYS long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);

DONESYS long sys_old_readdir(unsigned int, struct old_linux_dirent __user *, unsigned int);
DONESYS long sys_pselect6(int, fd_set __user *, fd_set __user *,
			     fd_set __user *, struct timespec __user *,
			     void __user *);
DONESYS long sys_ppoll(struct pollfd __user *, unsigned int,
			  struct timespec __user *, const sigset_t __user *,
			  size_t);


