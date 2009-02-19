/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#define MODULE_NAME "Hotplug"

#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/hashtable.h>

#define HOTPLUG_MAX_HOOKS 256

static struct {
	void (**hook) (void);
	void *fct;
} hooks_table[HOTPLUG_MAX_HOOKS];

static int hooks_index;
static DECLARE_MUTEX (hooks_lock);

void hook_register(void (**hk) (void), void *f)
{

	BUG_ON(hooks_index >= HOTPLUG_MAX_HOOKS);
	BUG_ON(hk == NULL);

	down(&hooks_lock);

	hooks_table[hooks_index].hook = hk;
	hooks_table[hooks_index].fct = f;

	hooks_index++;
	up(&hooks_lock);
}

void hooks_start(void)
{
	int i;

	down(&hooks_lock);
	for (i = 0; i < hooks_index; i++) {
		*(hooks_table[i].hook) = hooks_table[i].fct;
	}
}

void hooks_stop(void)
{
	int i;
	
	for(i = 0; i < hooks_index; i++){
		*(hooks_table[i].hook) = NULL;
	}
	up(&hooks_lock);
}

int hotplug_hooks_init(void)
{
	hooks_index = 0;
	return 0;
}

void hotplug_hooks_cleanup(void)
{
}
