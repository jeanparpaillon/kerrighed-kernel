#ifndef __KRG_SCHEDULER_HOOKS_H__
#define __KRG_SCHEDULER_HOOKS_H__

#ifdef CONFIG_KRG_SCHED
extern struct atomic_notifier_head kmh_calc_load;
extern struct atomic_notifier_head kmh_process_on;
extern struct atomic_notifier_head kmh_process_off;
#endif

#endif /* __KRG_SCHEDULER_HOOKS_H__ */
