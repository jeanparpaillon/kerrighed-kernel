#ifndef __KRG_KERRIGHED_SIGNAL_H__
#define __KRG_KERRIGHED_SIGNAL_H__

/* Kerrighed signal */

#ifdef CONFIG_KRG_EPM

#include <asm/signal.h>

struct siginfo;
struct pt_regs;
struct task_struct;

typedef void kerrighed_handler_t(int sig, struct siginfo *info,
				 struct pt_regs *regs);

extern kerrighed_handler_t *krg_handler[_NSIG];

int send_kerrighed_signal(int sig, struct siginfo *info, struct task_struct *t);

#endif /* CONFIG_KRG_EPM */

#endif /* __KRG_KERRIGHED_SIGNAL_H__ */
