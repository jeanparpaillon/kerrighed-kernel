/**  /proc/<pid>/<link> information management.
 *  @file proc_pid_link.h
 *
 *  @author David Margery
 */

#ifndef __PROC_PID_LINK_H__
#define __PROC_PID_LINK_H__

#include <linux/fs.h>

extern struct inode_operations krg_proc_pid_link_inode_operations;

int krg_proc_exe_link(struct inode *inode, struct path *path);
int krg_proc_cwd_link(struct inode *inode, struct path *path);
int krg_proc_root_link(struct inode *inode, struct path *path);

#endif /* __PROC_PID_LINK_H__ */
