#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#include <linux/compiler.h>
#include <asm/percpu.h>

#ifndef __ASSEMBLY__
struct task_struct;

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return percpu_read(current_task);
}

#ifdef CONFIG_KRG_EPM
#define krg_current (get_current()->effective_current)
#define current ({							\
	struct task_struct *__cur = get_current();			\
	__cur->effective_current ? __cur->effective_current : __cur;	\
})

#define krg_current_save(tmp) do {  \
		tmp = krg_current;  \
		krg_current = NULL; \
	} while (0)
#define krg_current_restore(tmp) do { \
		krg_current = tmp;    \
	} while (0)

#else /* !CONFIG_KRG_EPM */
#define current get_current()
#endif /* !CONFIG_KRG_EPM */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CURRENT_H */
