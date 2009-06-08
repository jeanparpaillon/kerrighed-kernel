#ifndef __GLOBAL_LOCK_H__
#define __GLOBAL_LOCK_H__

int global_lock_try_lock(unsigned long lock_id);
int global_lock_lock(unsigned long lock_id);
void global_lock_unlock(unsigned long lock_id);

#endif /* __GLOBAL_LOCK_H__ */
