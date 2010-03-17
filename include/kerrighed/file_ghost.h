/** File ghost interface
 *  @file file_ghost.h
 *
 *  Definition of file ghost structures and functions.
 *  @author Renaud Lottiaux
 */
#ifndef __FILE_GHOST__
#define __FILE_GHOST__

#include <asm/uaccess.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** File ghost private data
 */
struct file_ghost_data {
	struct file *file;              /**< File to save/load data to/from */
	int from_fd;
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int mkdir_chkpt_path(long app_id, unsigned int chkpt_sn);

char *get_chkpt_dir(long app_id, unsigned int chkpt_sn);

char *get_chkpt_filebase(long app_id,
			 unsigned int chkpt_sn,
			 const char *format,
			 ...);

/** Create a new file ghost.
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  access   Ghost access (READ/WRITE)
 *  @param  file     File to read/write data to/from.
 *
 *  @return        ghost_t if everything ok
 *                 ERR_PTR otherwise.
 */
ghost_t *create_file_ghost(int access,
			   long app_id,
			   unsigned int chkpt_sn,
			   const char *format,
			   ...);
void unlink_file_ghost(ghost_t *ghost);

/** Create a new file ghost.
 *  @author Matthieu Fertré, Renaud Lottiaux
 *
 *  @param  access   Ghost access (READ/WRITE)
 *  @param  fd       File descriptor to read/write data to/from.
 *
 *  @return        ghost_t if everything ok
 *                 ERR_PTR otherwise.
 */
ghost_t *create_file_ghost_from_fd(int access, unsigned int fd);

loff_t get_file_ghost_pos(ghost_t *ghost);
void set_file_ghost_pos(ghost_t *ghost, loff_t file_pos);

typedef struct {
	mm_segment_t fs;
	const struct cred *cred;
} ghost_fs_t;

void __set_ghost_fs(ghost_fs_t *oldfs);
int set_ghost_fs(ghost_fs_t *oldfs, uid_t fsuid, gid_t fsgid);
void unset_ghost_fs(const ghost_fs_t *oldfs);

#endif // __FILE_GHOST__
