#ifndef __REMOTE_CLONE_H__
#define __REMOTE_CLONE_H__

struct task_struct;

/* Used by migration */
void cleanup_vfork_done(struct task_struct *task);

#endif /* __REMOTE_CLONE_H__ */
