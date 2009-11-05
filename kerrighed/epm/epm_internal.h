#ifndef __EPM_INTERNAL_H__
#define __EPM_INTERNAL_H__

#ifdef CONFIG_KRG_EPM

#include <linux/thread_info.h>
#include <linux/slab.h>
#include <kerrighed/sys/types.h>
#include <asm/signal.h>

#define KRG_SIG_MIGRATE		SIGRTMIN
#define KRG_SIG_CHECKPOINT	(SIGRTMIN + 1)
#ifdef CONFIG_KRG_FD
#define KRG_SIG_FORK_DELAY_STOP	(SIGRTMIN + 2)
#endif

struct task_struct;

/* Used by migration and restart */
void __krg_children_share(struct task_struct *task);
int hide_process(struct task_struct *task);
void unhide_process(struct task_struct *task);
void __leave_all_relatives(struct task_struct *tsk);
void leave_all_relatives(struct task_struct *tsk);
void __join_local_relatives(struct task_struct *tsk);
void join_local_relatives(struct task_struct *tsk);

/* Copy-paste from kernel/fork.c + unstatify task_struct_cachep */

#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
# define alloc_task_struct()	kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
# define free_task_struct(tsk)	kmem_cache_free(task_struct_cachep, (tsk))
extern struct kmem_cache *task_struct_cachep;
#endif

#ifndef __HAVE_ARCH_THREAD_INFO_ALLOCATOR
static inline struct thread_info *alloc_thread_info(struct task_struct *tsk)
{
#ifdef CONFIG_DEBUG_STACK_USAGE
	gfp_t mask = GFP_KERNEL | __GFP_ZERO;
#else
	gfp_t mask = GFP_KERNEL;
#endif
	return (struct thread_info *)__get_free_pages(mask, THREAD_SIZE_ORDER);
}

static inline void free_thread_info(struct thread_info *ti)
{
	free_pages((unsigned long)ti, THREAD_SIZE_ORDER);
}
#endif

struct hotplug_context;

int epm_hotplug_init(void);
void epm_hotplug_cleanup(void);

int epm_signal_start(void);
void epm_signal_exit(void);
void signal_remove_local(void);

int epm_sighand_start(void);
void epm_sighand_exit(void);
void sighand_remove_local(void);

void epm_children_start(void);
void epm_children_exit(void);
void children_remove_local(void);

void epm_pidmap_start(void);
void epm_pidmap_exit(void);
int pidmap_map_add(struct hotplug_context *ctx);
int pidmap_map_remove_local(struct hotplug_context *ctx);

void epm_pid_start(void);
void epm_pid_exit(void);
void pid_remove_local(void);

int epm_procfs_start(void);
void epm_procfs_exit(void);

void register_remote_clone_hooks(void);
int epm_remote_clone_start(void);
void epm_remote_clone_exit(void);

int epm_migration_start(void);
void epm_migration_exit(void);

void register_checkpoint_hooks(void);

void application_cr_server_init(void);
void application_cr_server_finalize(void);
void application_remove_local(void);

#endif /* CONFIG_KRG_EPM */

#endif /* __EPM_INTERNAL_H__ */
