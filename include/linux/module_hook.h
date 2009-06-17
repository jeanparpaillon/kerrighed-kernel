#ifndef __MODULE_HOOK_H__
#define __MODULE_HOOK_H__

#ifdef CONFIG_MODULE_HOOK

typedef void module_hook_cb_t(unsigned long arg);
struct module;

struct module_hook_desc {
	module_hook_cb_t *callback;
	struct module *owner;
};

int module_hook_register(struct module_hook_desc *desc,
			 module_hook_cb_t *callback, struct module *owner);
void module_hook_unregister(struct module_hook_desc *desc,
			    module_hook_cb_t *callback);
void module_hook_call(struct module_hook_desc *desc, unsigned long arg);

#endif /* CONFIG_MODULE_HOOK */

#endif /* __MODULE_HOOK_H__ */
