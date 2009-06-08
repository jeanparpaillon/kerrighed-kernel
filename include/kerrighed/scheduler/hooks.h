#ifndef __KRG_SCHEDULER_HOOKS_H__
#define __KRG_SCHEDULER_HOOKS_H__

#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
#include <linux/module_hook.h>

extern struct module_hook_desc kmh_calc_load;
extern struct module_hook_desc kmh_process_on;
extern struct module_hook_desc kmh_process_off;
#endif

#endif /* __KRG_SCHEDULER_HOOKS_H__ */
