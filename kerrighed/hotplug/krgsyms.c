/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 */

#include <kerrighed/krgsyms.h>
#include <linux/module.h>
#include <linux/hashtable.h>
#include <linux/init.h>

/*****************************************************************************/
/*                                                                           */
/*                          KERRIGHED KSYM MANAGEMENT                        */
/*                                                                           */
/*****************************************************************************/


#define KRGSYMS_HTABLE_SIZE 256

static hashtable_t *krgsyms_htable;
static void* krgsyms_table[KRGSYMS_TABLE_SIZE];

int krgsyms_register(enum krgsyms_val v, void* p)
{
	if( (v < 0) || (v >= KRGSYMS_TABLE_SIZE) ){
		printk("krgsyms_register: Incorrect krgsym value (%d)\n", v);
		BUG();
		return -1;
	};

	if(krgsyms_table[v])
		printk("krgsyms_register_symbol(%d, %p): value already set in table\n",
					 v, p);

	if(hashtable_find(krgsyms_htable, (unsigned long)p) != NULL)
	{
		printk("krgsyms_register_symbol(%d, %p): value already set in htable\n",
					 v, p);
		BUG();
	}

	hashtable_add(krgsyms_htable, (unsigned long)p, (void*)v);
	krgsyms_table[v] = p;

	return 0;
};
EXPORT_SYMBOL(krgsyms_register);

int krgsyms_unregister(enum krgsyms_val v)
{
	void *p;

	if( (v < 0) || (v >= KRGSYMS_TABLE_SIZE) ){
		printk("krgsyms_unregister: Incorrect krgsym value (%d)\n", v);
		BUG();
		return -1;
	};

	p = krgsyms_table[v];
	krgsyms_table[v] = NULL;
	hashtable_remove(krgsyms_htable, (unsigned long)p);

	return 0;
};
EXPORT_SYMBOL(krgsyms_unregister);

enum krgsyms_val krgsyms_export(void* p)
{
	return (enum krgsyms_val)hashtable_find(krgsyms_htable, (unsigned long)p);
};

void* krgsyms_import(enum krgsyms_val v)
{
	if( (v < 0) || (v >= KRGSYMS_TABLE_SIZE) ){
		printk("krgsyms_import: Incorrect krgsym value (%d)\n", v);
		BUG();
		return NULL;
	};

	if ((v!=0) && (krgsyms_table[v] == NULL))
	{
		printk ("undefined krgsymbol (%d)\n", v);
		BUG();
	}

	return krgsyms_table[v];
};

static __init int init_krgsyms(void)
{
	krgsyms_htable = hashtable_new(KRGSYMS_HTABLE_SIZE);
	if (!krgsyms_htable)
		panic("Could not setup krgsyms table!\n");

	return 0;
};

pure_initcall(init_krgsyms);
