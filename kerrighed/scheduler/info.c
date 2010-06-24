/*
 *  kerrighed/scheduler/info.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#ifdef CONFIG_KRG_EPM
#include <kerrighed/ghost.h>
#endif
#include <kerrighed/scheduler/info.h>

struct krg_sched_info {
	struct list_head modules;
	struct list_head list;
	struct task_struct *task;
	struct rcu_head rcu;
};

static LIST_HEAD(sched_info_head);
static DEFINE_MUTEX(sched_info_list_mutex);

static struct kmem_cache *sched_info_cachep;

static LIST_HEAD(modules);
static DEFINE_SPINLOCK(modules_lock);
static u64 version;

static
struct krg_sched_module_info_type *module_info_type_get(const char *name)
{
	struct krg_sched_module_info_type *type;

	rcu_read_lock();
	list_for_each_entry_rcu(type, &modules, list)
		if (!strcmp(type->name, name)) {
			if (!try_module_get(type->owner))
				type = NULL;
			rcu_read_unlock();
			return type;
		}
	rcu_read_unlock();
	return NULL;
}

static void __add_module_info(struct krg_sched_info *info,
			      struct krg_sched_module_info *mod_info,
			      struct list_head *next,
			      struct krg_sched_module_info_type *type)
{
	mod_info->type = type;
	list_add(&mod_info->instance_list, &type->instance_head);
	list_add_tail_rcu(&mod_info->info_list, next);
}

static void add_missing_mod_info(struct krg_sched_info *info,
				 struct krg_sched_module_info_type *type)
{
	struct krg_sched_module_info *mod_info, *new_mod_info;
	struct list_head *at;
	int ret;

	/* Check that no mod_info of this type already exists */
	ret = -1;
	rcu_read_lock();
	list_for_each_entry_rcu(mod_info, &info->modules, info_list) {
		ret = strcmp(type->name, mod_info->type->name);
		if (ret <= 0)
			break;
	}
	rcu_read_unlock();
	if (ret == 0)
		return;

	/* Create one and insert it in lexicographical order */
	new_mod_info = type->copy(info->task, NULL);
	if (new_mod_info) {
		at = &info->modules;
		spin_lock_irq(&modules_lock);
		list_for_each_entry(mod_info, &info->modules, info_list)
			if (strcmp(type->name, mod_info->type->name) < 0) {
				at = &mod_info->info_list;
				break;
			}
		__add_module_info(info, new_mod_info, at, type);
		spin_unlock_irq(&modules_lock);
	}
}

int krg_sched_module_info_register(struct krg_sched_module_info_type *type)
{
	struct list_head *where;
	struct krg_sched_module_info_type *pos;
	struct krg_sched_info *info;
	unsigned long flags;

	if (!strlen(type->name))
		return -EINVAL;

	INIT_LIST_HEAD(&type->instance_head);

	mutex_lock(&sched_info_list_mutex);
	spin_lock_irqsave(&modules_lock, flags);
	/*
	 * Lexicographically sort the list so that import_krg_sched_info does
	 * not need to do a complex sort of imported module infos
	 */
	where = &modules;
	list_for_each_entry(pos, &modules, list) {
		if (strcmp(pos->name, type->name) > 0)
			where = &pos->list;
	}
	list_add_tail_rcu(&type->list, where);
	spin_unlock_irqrestore(&modules_lock, flags);

	/*
	 * Matches smp_read_barrier_depends() in krg_sched_info_copy(), which
	 * parses the modules list with RCU lock only.
	 * list_add_tail_rcu() does not ensure that the new module is seen in
	 * the list before version is incremented.
	 * Ensures that version is seen incremented after the module is
	 * registered in the list.
	 */
	smp_wmb();
	version++;

	list_for_each_entry(info, &sched_info_head, list)
		add_missing_mod_info(info, type);
	mutex_unlock(&sched_info_list_mutex);

	return 0;
}
EXPORT_SYMBOL(krg_sched_module_info_register);

/*
 * must only be called at module unloading (See comment in
 * krg_sched_info_copy)
 */
void krg_sched_module_info_unregister(struct krg_sched_module_info_type *type)
{
	struct krg_sched_module_info *mod_info, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&modules_lock, flags);
	list_del_rcu(&type->list);

	/* Remove all existing module_info of this type from their task */
	list_for_each_entry(mod_info, &type->instance_head, instance_list)
		list_del_rcu(&mod_info->info_list);
	spin_unlock_irqrestore(&modules_lock, flags);

	synchronize_rcu();
	/*
	 * Now nobody can be using any of the module_info of this type, nor can
	 * add a new one.
	 */

	list_for_each_entry_safe(mod_info, tmp,
				 &type->instance_head, instance_list) {
		list_del(&mod_info->instance_list);
		type->free(mod_info);
	}
}
EXPORT_SYMBOL(krg_sched_module_info_unregister);

/* Must be called under rcu_read_lock() */
struct krg_sched_module_info *
krg_sched_module_info_get(struct task_struct *task,
			  struct krg_sched_module_info_type *type)
{
	struct krg_sched_info *info;
	struct krg_sched_module_info *mod_info;

	info = rcu_dereference(task->krg_sched);
	if (!info)
		return NULL;
	list_for_each_entry_rcu(mod_info, &info->modules, info_list)
		if (mod_info->type == type)
			return mod_info;
	return NULL;
}
EXPORT_SYMBOL(krg_sched_module_info_get);

static struct krg_sched_info *alloc_sched_info(struct task_struct *task,
					       int gfp_flags)
{
	struct krg_sched_info *info;

	info = kmem_cache_alloc(sched_info_cachep, gfp_flags);
	if (info) {
		INIT_LIST_HEAD(&info->modules);
		info->task = task;
	}
	return info;
}

/* Must be called under rcu_read_lock() */
/*
 * We are not interested in mod_infos from unloading modules, and the mod_info
 * returned must survive a temporary release of RCU read lock, so we grab a
 * reference on the returned mod_info's module.
 * Caller must release this reference after the last call to next_mod_info().
 */
static struct krg_sched_module_info *
next_mod_info(struct krg_sched_info *info,
	      struct krg_sched_module_info *mod_info)
{
	struct krg_sched_module_info *next_info;
	struct list_head *pos;

	if (!info)
		return NULL;

	if (mod_info) {
		/*
		 * Accessing mod_info remains safe as long as we hold RCU read
		 * lock.
		 */
		module_put(mod_info->type->owner);
		pos = &mod_info->info_list;
	} else {
		pos = &info->modules;
	}

	list_for_each_continue_rcu(pos, &info->modules) {
		next_info = list_entry(pos,
				       struct krg_sched_module_info,
				       info_list);
		if (try_module_get(next_info->type->owner))
			return next_info;
	}

	return NULL;
}

static void add_module_info(struct krg_sched_info *info,
			    struct krg_sched_module_info *mod_info,
			    struct krg_sched_module_info_type *type)
{
	spin_lock_irq(&modules_lock);
	__add_module_info(info, mod_info, &info->modules, type);
	spin_unlock_irq(&modules_lock);
}

/*
 * Algorithm similar to krg_sched_info_copy()'s normal path, with only new
 * module infos.
 */
static void add_missing_mod_infos(struct krg_sched_info *info)
{
	struct task_struct *task;
	struct list_head *pos;
	struct krg_sched_module_info_type *type;
	struct krg_sched_module_info *mod_info, *new_mod_info;

	task = info->task;
	rcu_read_lock();
	mod_info = next_mod_info(info, NULL);
	for (pos = rcu_dereference(modules.next);
	     pos != &modules;
	     pos = rcu_dereference(pos->next)) {
		type = list_entry(pos, struct krg_sched_module_info_type, list);
		if (!try_module_get(type->owner))
			continue;
		rcu_read_unlock();

		if (mod_info && mod_info->type == type) {
			rcu_read_lock();
			mod_info = next_mod_info(info, mod_info);
		} else {
			new_mod_info = type->copy(task, NULL);
			if (new_mod_info) {
				struct list_head *at = &info->modules;
				if (mod_info)
					at = &mod_info->info_list;
				spin_lock_irq(&modules_lock);
				__add_module_info(info, new_mod_info, at, type);
				spin_unlock_irq(&modules_lock);
			}
			rcu_read_lock();
		}

		module_put(type->owner);
	}
	rcu_read_unlock();
	if (mod_info)
		module_put(mod_info->type->owner);

}

static void complete_and_commit_sched_info(struct krg_sched_info *info,
					   u64 start_version)
{
	mutex_lock(&sched_info_list_mutex);
	if (unlikely(start_version < version))
		add_missing_mod_infos(info);
	list_add(&info->list, &sched_info_head);
	mutex_unlock(&sched_info_list_mutex);

	rcu_assign_pointer(info->task->krg_sched, info);
}

int krg_sched_info_copy(struct task_struct *task)
{
	struct krg_sched_info *info;
	struct krg_sched_info *new_info;
	struct list_head *pos;
	struct krg_sched_module_info_type *type;
	struct krg_sched_module_info *mod_info, *new_mod_info;
	u64 start_version;

	rcu_assign_pointer(task->krg_sched, NULL);

	if (krg_current) {
		rcu_assign_pointer(task->krg_sched, krg_current->krg_sched);
		return 0;
	}

	if (!task->nsproxy->krg_ns)
		return 0;

	/* Kernel threads do not need krg_sched_info */
	/*
	 * This test is not really clean, since at this stage task->mm points to
	 * the mm of the caller (parent or sister task), but we only want to
	 * know if the new task will have an mm or not.
	 */
	if (task->flags & PF_KTHREAD)
		return 0;

	new_info = alloc_sched_info(task, GFP_KERNEL);
	if (!new_info)
		return -ENOMEM;

	start_version = version;
	/*
	 * Matches smp_wmb() in krg_sched_module_info_register()
	 * Ensures that version is not seen incremented before the new module
	 * responsible for it is seen added to the modules list.
	 */
	smp_read_barrier_depends();

	/*
	 * Parse simultaneously the list of registered modules and the list of
	 * current's modules to copy/create the infos for the new task
	 *
	 * Both lists are sorted in the same order of types, and all current's
	 * modules have their type in the registered modules list. This is
	 * guaranteed as long as no module calls
	 * krg_sched_module_info_unregister() outside module
	 * unloading. Conversely, some types may not have an info for
	 * current.
	 */

	/*
	 * Some modules may appear/disappear and per module internal info may be
	 * changed or disappear. However a module info can be removed from the
	 * list but cannot disappear as long as its module is not unloading or
	 * RCU is locked.
	 */
	rcu_read_lock();
	info = rcu_dereference(task->krg_sched);
	mod_info = next_mod_info(info, NULL);
	/*
	 * We do not use list_for_each(_entry)_rcu because we must avoid any
	 * prefetch optimization that would load an element that could be freed
	 * while RCU is unlocked.
	 */
	for (pos = rcu_dereference(modules.next);
	     pos != &modules;
	     pos = rcu_dereference(pos->next)) {
		type = list_entry(pos, struct krg_sched_module_info_type, list);
		if (!try_module_get(type->owner))
			continue;
		/*
		 * Now we are sure that type won't disappear, as long as
		 * module_type_unregister is not called outside moudule
		 * unloading.
		 */
		rcu_read_unlock();

		if (mod_info && mod_info->type == type) {
			new_mod_info = type->copy(task, mod_info);
			rcu_read_lock();
			mod_info = next_mod_info(info, mod_info);
		} else {
			new_mod_info = type->copy(task, NULL);
			rcu_read_lock();
		}
		if (new_mod_info)
			add_module_info(new_info, new_mod_info, type);

		module_put(type->owner);
	}
	rcu_read_unlock();
	if (mod_info)
		/*
		 * next_mod_info() took a reference on the module to survive the
		 * temporary release of RCU read lock.
		 */
		module_put(mod_info->type->owner);

	complete_and_commit_sched_info(new_info, start_version);
	return 0;
}

static void free_sched_info(struct krg_sched_info *info)
{
	struct krg_sched_module_info *mod_info, *tmp;
	struct krg_sched_module_info_type *type;
	unsigned long flags;

	/* Prevent an unloading module type from changing the list */
	spin_lock_irqsave(&modules_lock, flags);
	list_for_each_entry_safe(mod_info, tmp,
				 &info->modules, info_list) {
		list_del(&mod_info->instance_list);
		list_del(&mod_info->info_list);
		type = mod_info->type;
		type->free(mod_info);
	}
	spin_unlock_irqrestore(&modules_lock, flags);

	kmem_cache_free(sched_info_cachep, info);
}

static void delayed_free_sched_info(struct rcu_head *rhp)
{
	struct krg_sched_info *info =
		container_of(rhp, struct krg_sched_info, rcu);
	free_sched_info(info);
}

void krg_sched_info_free(struct task_struct *task)
{
	struct krg_sched_info *info = rcu_dereference(task->krg_sched);

#ifdef CONFIG_KRG_EPM
	if (krg_current)
		return;
#endif

	if (!info)
		return;

	mutex_lock(&sched_info_list_mutex);
	list_del(&info->list);
	mutex_unlock(&sched_info_list_mutex);
	rcu_assign_pointer(task->krg_sched, NULL);
	call_rcu(&info->rcu, delayed_free_sched_info);
}

#ifdef CONFIG_KRG_EPM

int export_krg_sched_info(struct epm_action *action, ghost_t *ghost,
			  struct task_struct *task)
{
	struct krg_sched_info *info;
	struct krg_sched_module_info *mod_info;
	struct krg_sched_module_info_type *type;
	struct list_head *mods;
	struct list_head *pos;
	size_t type_name_len;
	int err;

	rcu_read_lock();
	info = rcu_dereference(task->krg_sched);
	if (!info)
		goto end_of_list;
	/*
	 * avoid using list_for_each_entry_rcu to avoid prefetching memory that
	 * may be freed whil RCU is unlocked
	 */
	mods = &info->modules;
	for (pos = rcu_dereference(mods->next);
	     pos != mods;
	     pos = rcu_dereference(pos->next)) {
		mod_info = list_entry(pos, typeof(*mod_info), info_list);
		type = mod_info->type;
		if (!try_module_get(type->owner))
			continue;
		/*
		 * Now we are sure that mod_info and type won't disappear, as
		 * long as module_type_unregister is not called outside moudule
		 * unloading.
		 */
		rcu_read_unlock();

		type_name_len = strlen(type->name);
		err = ghost_write(ghost, &type_name_len, sizeof(type_name_len));
		if (err)
			goto err_module;
		err = ghost_write(ghost, type->name, type_name_len + 1);
		if (err)
			goto err_module;
		err = type->export(action, ghost, mod_info);
		if (err)
			goto err_module;

		rcu_read_lock();
		module_put(type->owner);
	}
end_of_list:
	rcu_read_unlock();

	/* end-of-list marker */
	type_name_len = 0;
	err = ghost_write(ghost, &type_name_len, sizeof(type_name_len));
out:
	return err;

err_module:
	module_put(type->owner);
	goto out;
}

int import_krg_sched_info(struct epm_action *action, ghost_t *ghost,
			  struct task_struct *task)
{
	struct krg_sched_info *info;
	struct krg_sched_module_info_type *type;
	struct krg_sched_module_info *mod_info;
	size_t type_name_len;
	size_t max_type_name_len = 0;
	char *type_name = NULL;
	int err;

	info = alloc_sched_info(task, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	while (1) {
		err = ghost_read(ghost, &type_name_len, sizeof(type_name_len));
		if (err)
			break;
		if (!type_name_len)
			/* end-of-list marker */
			break;
		if (type_name_len > max_type_name_len) {
			kfree(type_name);
			type_name = kmalloc(type_name_len + 1, GFP_KERNEL);
			if (!type_name) {
				err = -ENOMEM;
				break;
			}
			max_type_name_len = type_name_len;
		}
		err = ghost_read(ghost, type_name, type_name_len + 1);
		if (err)
			break;

		type = module_info_type_get(type_name);
		if (!type) {
			err = -ENODEV;
			break;
		}

		mod_info = type->import(action, ghost, task);
		if (IS_ERR(mod_info)) {
			err = PTR_ERR(mod_info);
			module_put(type->owner);
			break;
		}
		if (mod_info)
			add_module_info(info, mod_info, type);
		module_put(type->owner);
	}
	kfree(type_name);

	if (!err)
		complete_and_commit_sched_info(info, 0);
	else
		free_sched_info(info);

	return err;
}

void post_import_krg_sched_info(struct task_struct *task)
{
	mutex_lock(&sched_info_list_mutex);
	task->krg_sched->task = task;
	mutex_unlock(&sched_info_list_mutex);
}

void unimport_krg_sched_info(struct task_struct *task)
{
	krg_sched_info_free(task);
}

#endif /* CONFIG_KRG_EPM */

int krg_sched_info_start(void)
{
	sched_info_cachep = KMEM_CACHE(krg_sched_info, SLAB_PANIC);

	return 0;
}

void krg_sched_info_exit(void)
{
}
