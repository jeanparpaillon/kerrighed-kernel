#ifndef __GLOBAL_LOCK_H__
#define __GLOBAL_LOCK_H__

enum {
	GLOBAL_LOCK_SCHED,
	GLOBAL_LOCK_MAX,
};

int global_lock_try_writelock(unsigned long lock_id);
int global_lock_writelock(unsigned long lock_id);
int global_lock_readlock(unsigned long lock_id);
void global_lock_unlock(unsigned long lock_id);

#endif /* __GLOBAL_LOCK_H__ */
