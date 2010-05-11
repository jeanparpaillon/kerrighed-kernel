#ifndef __KRG_SCHEDULER_HOOKS_H__
#define __KRG_SCHEDULER_HOOKS_H__

#if defined(CONFIG_KRG_SCHED) && defined(CONFIG_MODULE_HOOK)
extern struct atomic_notifier_head kmh_calc_load;
extern struct atomic_notifier_head kmh_process_on;
extern struct atomic_notifier_head kmh_process_off;
#endif

#endif /* __KRG_SCHEDULER_HOOKS_H__ */
