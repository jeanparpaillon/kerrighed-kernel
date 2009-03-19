#ifndef __PROC_INTERNAL_H__
#define __PROC_INTERNAL_H__

#ifdef CONFIG_KRG_PROC

void proc_task_start(void);
void proc_task_exit(void);
void register_task_hooks(void);

void proc_krg_exit_start(void);
void proc_krg_exit_exit(void);
void register_krg_exit_hooks(void);

void proc_remote_syscalls_start(void);
void register_remote_syscalls_hooks(void);

#ifdef CONFIG_KRG_EPM
void pid_management_start(void);
void pid_management_exit(void);
void register_pid_hooks(void);

void proc_children_start(void);
void proc_children_exit(void);
void register_children_hooks(void);

int proc_signal_start(void);
void proc_signal_exit(void);
void register_signal_hooks(void);

int proc_sighand_start(void);
void proc_sighand_exit(void);
void register_sighand_hooks(void);

int proc_krg_fork_start(void);
void proc_krg_fork_exit(void);
void register_krg_fork_hooks(void);
#endif /* CONFIG_KRG_EPM */

#endif /* CONFIG_KRG_PROC */

#endif /* __PROC_INTERNAL_H__ */
