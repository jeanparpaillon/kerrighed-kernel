#ifndef __KRG_SYSCALLS__

#define __KRG_SYSCALLS__

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

typedef int (*proc_service_function_t) (void *arg);

struct proc_service_entry {
	proc_service_function_t fct;
	char label[32];
	unsigned long count;
	bool restricted;
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct proc_dir_entry *proc_services;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int __register_proc_service(unsigned int cmd, proc_service_function_t fun,
			    bool restricted);
int register_proc_service(unsigned int cmd, proc_service_function_t fun);
int unregister_proc_service(unsigned int cmd);

int krg_syscalls_init(void);
int krg_syscalls_finalize(void);

#endif				/* __KRG_SYSCALLS__ */
