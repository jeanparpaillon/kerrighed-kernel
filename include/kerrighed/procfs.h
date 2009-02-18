#ifndef __TOOLS_PROCFS__
#define __TOOLS_PROCFS__

#ifdef __KERNEL__

#include <linux/ioctl.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct proc_dir_entry *proc_kerrighed;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int kerrighed_proc_init(void);
void kerrighed_proc_finalize(void);

void procfs_deltree(struct proc_dir_entry *entry);

#endif				//  __KERNEL__

#endif				/* __TOOLS_PROCFS__ */
