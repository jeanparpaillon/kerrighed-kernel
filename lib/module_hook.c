/*
 *  lib/module_hook.c
 *
 *  Copyright (C) 2007 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/errno.h>
#include <linux/module_hook.h>

static DEFINE_SPINLOCK(hooks_lock);

int module_hook_register(struct module_hook_desc *desc,
			 module_hook_cb_t *callback,
			 struct module *owner)
{
	unsigned long flags;
	int err = -EEXIST;

	spin_lock_irqsave(&hooks_lock, flags);
	if (!desc->callback) {
		desc->callback = callback;
		desc->owner = owner;
		err = 0;
	}
	spin_unlock_irqrestore(&hooks_lock, flags);

	return err;
}
EXPORT_SYMBOL(module_hook_register);

/* Must only be called at module unloading */
void module_hook_unregister(struct module_hook_desc *desc,
			    module_hook_cb_t *callback)
{
	unsigned long flags;

	spin_lock_irqsave(&hooks_lock, flags);
	if (desc->callback == callback)
		desc->callback = NULL;
	spin_unlock_irqrestore(&hooks_lock, flags);
}
EXPORT_SYMBOL(module_hook_unregister);

void module_hook_call(struct module_hook_desc *desc, unsigned long arg)
{
	unsigned long flags;
	int exec = 0;

	spin_lock_irqsave(&hooks_lock, flags);
	if (desc->callback && try_module_get(desc->owner))
		exec = 1;
	spin_unlock_irqrestore(&hooks_lock, flags);

	if (exec) {
		desc->callback(arg);
		module_put(desc->owner);
	}
}
EXPORT_SYMBOL(module_hook_call);
