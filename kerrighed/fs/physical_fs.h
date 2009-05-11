/** Access to Physical File System management.
 *  @file physical_fs.h
 *
 *  @author Renaud Lottiaux
 */

#ifndef __PHYSICAL_FS__
#define __PHYSICAL_FS__

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

char *physical_d_path(const struct path *path, char *tmp);

struct file *open_physical_file(char *filename,
				int flags, int mode, uid_t fsuid, gid_t fsgid);

int close_physical_file(struct file *file);

int remove_physical_file(struct file *file);

int remove_physical_dir(struct file *file);

#endif // __PHYSICAL_FS__
