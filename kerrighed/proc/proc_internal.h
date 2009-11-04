#ifndef __PROC_INTERNAL_H__
#define __PROC_INTERNAL_H__

#ifdef CONFIG_KRG_PROC

void proc_task_start(void);
void proc_task_exit(void);
void proc_task_remove_local(void);

void proc_krg_exit_start(void);
void proc_krg_exit_exit(void);

void proc_remote_syscalls_start(void);
void register_remote_syscalls_hooks(void);

#endif /* CONFIG_KRG_PROC */

#endif /* __PROC_INTERNAL_H__ */
