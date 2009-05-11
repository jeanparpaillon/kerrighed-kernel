/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/posix_types.h>

struct file;
#ifdef CONFIG_KRG_FAF
struct files_struct;
#endif
extern void __fput(struct file *);
extern void fput(struct file *);
extern void drop_file_write_access(struct file *file);

struct file_operations;
struct vfsmount;
struct dentry;
extern int init_file(struct file *, struct vfsmount *mnt,
		struct dentry *dentry, fmode_t mode,
		const struct file_operations *fop);
extern struct file *alloc_file(struct vfsmount *, struct dentry *dentry,
		fmode_t mode, const struct file_operations *fop);

static inline void fput_light(struct file *file, int fput_needed)
{
	if (unlikely(fput_needed))
		fput(file);
}

extern struct file *fget(unsigned int fd);
extern struct file *fget_light(unsigned int fd, int *fput_needed);
extern void set_close_on_exec(unsigned int fd, int flag);
extern void put_filp(struct file *);
extern int alloc_fd(unsigned start, unsigned flags);
extern int get_unused_fd(void);
#ifdef CONFIG_KRG_FAF
int __get_unused_fd(struct files_struct *files);
#endif
#define get_unused_fd_flags(flags) alloc_fd(0, (flags))
#ifdef CONFIG_KRG_FAF
extern void __put_unused_fd(struct files_struct *files, unsigned int fd);
#endif
extern void put_unused_fd(unsigned int fd);
#ifdef CONFIG_KRG_FAF
extern void __fd_install(struct files_struct *files,
			 unsigned int fd, struct file *file);
#endif
extern void fd_install(unsigned int fd, struct file *file);

#ifdef CONFIG_KRG_DVFS
struct fdtable;
int count_open_files(struct fdtable *fdt);

struct fdtable * alloc_fdtable(unsigned int nr);
#endif

#endif /* __LINUX_FILE_H */
