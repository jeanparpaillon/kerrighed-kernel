/**  /proc/<pid>/fd information management.
 *  @file proc_pid_fd.h
 *
 *  @author David Margery
 */

#ifndef __PROC_PID_FD_H__
#define __PROC_PID_FD_H__

#include <linux/fs.h>

extern struct file_operations krg_proc_fd_operations;
extern struct inode_operations krg_proc_fd_inode_operations;

#endif /* __PROC_PID_FD_H__ */
