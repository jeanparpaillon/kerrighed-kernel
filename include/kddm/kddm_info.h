#ifndef __KDDM_INFO_H__
#define __KDDM_INFO_H__

extern int (*kh_copy_kddm_info)(unsigned long clone_flags,
				struct task_struct * tsk);

extern struct kmem_cache *kddm_info_cachep;

#endif /* __KDDM_INFO_H__ */
