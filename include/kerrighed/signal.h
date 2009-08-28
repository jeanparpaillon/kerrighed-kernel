#ifndef __KERRIGHED_SIGNAL_H__
#define __KERRIGHED_SIGNAL_H__

#ifdef CONFIG_KRG_EPM

#include <kddm/kddm_types.h>

/* signal_struct sharing */

struct signal_struct;
struct task_struct;
struct pid;

void krg_signal_alloc(struct task_struct *task, struct pid *pid,
		      unsigned long clone_flags);
void krg_signal_share(struct signal_struct *sig);
struct signal_struct *krg_signal_exit(struct signal_struct *sig);
struct signal_struct *krg_signal_readlock(struct signal_struct *sig);
struct signal_struct *krg_signal_writelock(struct signal_struct *sig);
void krg_signal_unlock(struct signal_struct *sig);
void krg_signal_pin(struct signal_struct *sig);
void krg_signal_unpin(struct signal_struct *sig);

/* sighand_struct sharing */

struct sighand_struct;

void krg_sighand_alloc(struct task_struct *task, unsigned long clone_flags);
void krg_sighand_alloc_unshared(struct task_struct *task,
				struct sighand_struct *newsig);
void krg_sighand_share(struct task_struct *task);
objid_t krg_sighand_exit(struct sighand_struct *sig);
void krg_sighand_cleanup(struct sighand_struct *sig);
struct sighand_struct *krg_sighand_readlock(objid_t id);
struct sighand_struct *krg_sighand_writelock(objid_t id);
void krg_sighand_unlock(objid_t id);
void krg_sighand_pin(struct sighand_struct *sig);
void krg_sighand_unpin(struct sighand_struct *sig);

/* Used by restart */
struct sighand_struct *cr_sighand_alloc(void);
void cr_sighand_free(objid_t id);

#endif /* CONFIG_KRG_EPM */

#endif /* __KERRIGHED_SIGNAL_H__ */
