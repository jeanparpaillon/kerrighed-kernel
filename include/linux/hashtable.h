/** Hashtable management interface
 *  @file hashtable.h
 *
 *  Definition of hashtable management functions.
 *  @author Viet Hoa Dinh, Renaud Lottiaux
 */

#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <linux/stddef.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <asm/system.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


#define HASHTABLE_SIZE 1024


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


/** Hashtable linked list element */
struct hash_list {
	unsigned long hash;        /* Key of stored data */
	void * data;               /* Data stored in the table */
	struct hash_list * next;   /* Next stored data */
};

/** Hashtable Structure */
typedef struct hashtable_t {
	spinlock_t lock;                /** Structure lock */
	struct hash_list * table;       /** Hash table */
	unsigned long hashtable_size;   /** Size of the hash table */
	unsigned long flags[NR_CPUS];
} hashtable_t;

#define hashtable_lock(table) spin_lock (&table->lock)
#define hashtable_unlock(table) spin_unlock (&table->lock)

#define hashtable_lock_bh(table) spin_lock_bh (&table->lock)
#define hashtable_unlock_bh(table) spin_unlock_bh (&table->lock)

#define hashtable_lock_irq(table) spin_lock_irq (&table->lock)
#define hashtable_unlock_irq(table) spin_unlock_irq (&table->lock)

#define hashtable_lock_irqsave(table) spin_lock_irqsave (&table->lock, table->flags[smp_processor_id()])
#define hashtable_unlock_irqrestore(table) spin_unlock_irqrestore (&table->lock, table->flags[smp_processor_id()])

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Create a new hash table
 *  @author Viet Hoa Dinh
 * 
 *  @param hashtable_size  Size of the hashtable to create.
 *
 *  @return  A pointer to the newly created hash table.
 */
hashtable_t *_hashtable_new(unsigned long hashtable_size);
static inline hashtable_t * hashtable_new(unsigned long hashtable_size)
{
	hashtable_t *ht;

	ht = _hashtable_new(hashtable_size);
	if (ht)
		spin_lock_init(&ht->lock);

	return ht;
}



/** Free a hash table
 *  @author Viet Hoa Dinh
 * 
 *  @param table  The table to free
 */
void hashtable_free(hashtable_t * table);



/** Add an element to a hash table
 *  @author Viet Hoa Dinh
 * 
 *  @param table  The table to add the element in.
 *  @param hash   The element key.
 *  @param data   The element to add in the table
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int __hashtable_add(hashtable_t * table, unsigned long hash, void * data);

static inline int hashtable_add(hashtable_t * table, unsigned long hash,
			       void * data)
{
	int r;

	hashtable_lock_irqsave (table);

	r = __hashtable_add (table, hash, data);

	hashtable_unlock_irqrestore (table);

	return r;
}

/** Add an element to a hash table
 *  It fails with EEXIST if there is already an element with the same hash.
 *
 *  @author Matthieu Fertré
 *
 *  @param table  The table to add the element in.
 *  @param hash   The element key.
 *  @param data   The element to add in the table
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int __hashtable_add_unique(hashtable_t *table, unsigned long hash, void *data);

static inline int hashtable_add_unique(hashtable_t *table, unsigned long hash,
				       void *data)
{
	int r;

	hashtable_lock_irqsave(table);

	r = __hashtable_add_unique(table, hash, data);

	hashtable_unlock_irqrestore(table);

	return r;
}

/** Remove an element from a hash table
 *  @author Viet Hoa Dinh
 * 
 *  @param table  The table to remove the element from.
 *  @param hash   The element key.
 *
 *  @return  The data removed.
 *           NULL value otherwise.
 */
void *__hashtable_remove(hashtable_t * table, unsigned long hash);

static inline void * hashtable_remove(hashtable_t * table, unsigned long hash)
{
	void *data;

	hashtable_lock_irqsave (table);

	data = __hashtable_remove (table, hash);

	hashtable_unlock_irqrestore (table);

	return data;
}



/** Find an element in a hash table
 *  @author Viet Hoa Dinh
 * 
 *  @param table  The table to search the element in.
 *  @param hash   The element key.
 *
 *  @return  A pointer to the data, if in the table.
 *           NULL if data not found.
 */
void * __hashtable_find(hashtable_t * table, unsigned long hash);

static inline void * hashtable_find(hashtable_t * table, unsigned long hash)
{
	void * r;

	hashtable_lock_irqsave (table);

	r = __hashtable_find (table, hash);

	hashtable_unlock_irqrestore (table);

	return r;
}



/** Find the element just following the given hash in hash order.
 *  @author Renaud Lottiaux
 *
 *  @param table  The table to search the element in.
 *  @param hash   The element key.
 *
 *  @return  A pointer to the data, if in the table.
 *           NULL if data not found.
 *           Hash of the found element is returned in hash_found.
 */
void * __hashtable_find_next(hashtable_t * table, unsigned long hash,
			     unsigned long *hash_found);
static inline void * hashtable_find_next(hashtable_t * table,
					 unsigned long hash,
					 unsigned long *hash_found)
{
	void * r;

	hashtable_lock_irqsave (table);

	r = __hashtable_find_next (table, hash, hash_found);

	hashtable_unlock_irqrestore (table);

	return r;
}


/** Apply a function on each hash table key.
 *  @author Viet Hoa Dinh, Pascal Gallard
 * 
 *  @param table  The table to work with.
 *  @param func   The function to apply.
 *  @param data   Data to send to the given function.
 */
void __hashtable_foreach_key(hashtable_t * table,
			     void (* func)(unsigned long, void *),
			     void * data);



/** Apply a function on each hash table element.
 *  @author Viet Hoa Dinh, Pascal Gallard
 * 
 *  @param table  The table to work with.
 *  @param func   The function to apply.
 *  @param data   Data to send to the given function.
 */
void __hashtable_foreach_data(hashtable_t * table,
			      void (* fun)(void *, void *),
			      void * data);

/** Apply a function on each hash table pair (key,element).
 *  @author Louis Rilling
 *
 *  @param table  The table to work with.
 *  @param func   The function to apply.
 *  @param data   Data to send to the given function.
 */
void __hashtable_foreach_key_data(hashtable_t * table,
				  void (* func)(unsigned long, void *, void *),
				  void * data);

/** Find an element of the hashtable that staifies a criteria
 *  @author David Margery
 * 
 *  @param table  The table to work with.
 *  @param func   The function to apply.
 *  @param data   Data to send to the given function.
 */
void * hashtable_find_data(hashtable_t * table,
			   int (* fun)(void *, void *),
			   void * data);


#endif // __HASHTABLE_H__
