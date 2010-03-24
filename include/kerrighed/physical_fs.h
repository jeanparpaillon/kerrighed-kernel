/** Access to Physical File System management.
 *  @file physical_fs.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __PHYSICAL_FS__
#define __PHYSICAL_FS__

#include <linux/path.h>
#include <linux/types.h>

struct nsproxy;
struct file;

struct prev_root {
	struct path path;
	struct nsproxy *nsproxy;
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

char *physical_d_path(const struct path *path, char *tmp, bool del_ok);

void get_physical_root(struct path *root);

void chroot_to_physical_root(struct prev_root *prev_root);
void chroot_to_prev_root(const struct prev_root *prev_root);

struct file *open_physical_file(char *filename,
				int flags, int mode, uid_t fsuid, gid_t fsgid);

int close_physical_file(struct file *file);

int remove_physical_file(struct file *file);

int remove_physical_dir(struct file *file);

#endif // __PHYSICAL_FS__
