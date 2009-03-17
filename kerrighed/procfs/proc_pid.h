/** Global /proc/<pid> information management.
 *  @file proc_pid.h
 *
 *  @author David Margery
 */

#ifndef __PROC_PID_H__
#define __PROC_PID_H__

#include <linux/proc_fs.h>
#include <linux/fs.h>

static inline
struct proc_distant_pid_info *get_krg_proc_task(struct inode *inode)
{
	return &PROC_I(inode)->distant_proc;
}

int proc_pid_init(void);
int proc_pid_finalize(void);

#endif /* __PROC_PID_H__ */
