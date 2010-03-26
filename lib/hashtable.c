/*
 *  Copyright (C) 2006-2007, Pascal Gallard, Kerlabs.
 *  Copyright (C) 2008, Renaud Lottiaux, Kerlabs.
 */

#include <linux/module.h>
#include <linux/hashtable.h>


/*****************************************************************************/
/*                                                                           */
/*                           KERRIGHED HASH TABLES                           */
/*                                                                           */
/*****************************************************************************/


static struct hash_list HASH_LISTHEAD_NEW = { 0, NULL, NULL };


/** Add a new element in a hash table linked list.
 *  @author Viet Hoa Dinh
 * 
 *  The function must be called with the lock taken.
 *
 *  @param table  The table to add the element in.
 *  @param hash   The element key.
 *  @param data   The element to add in the table
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static inline int hash_list_add(hashtable_t * table,
                                unsigned long hash,
				void * data)
{
	struct hash_list * ht;
	int index;

	index = hash % table->hashtable_size;

	ht = kmalloc(sizeof(struct hash_list), GFP_ATOMIC);
	if (ht == NULL)
		return -ENOMEM;

	ht->hash = hash;
	ht->data = data;
	ht->next = table->table[index].next;

	table->table[index].next = ht;

	return 0;
}



/** Remove an element from a hash table linked list.
 *  @author Viet Hoa Dinh
 *
 *  The function must be called with the lock taken.
 *
 *  @param table  The table to remove the element from.
 *  @param hash   The element key.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
static inline void *hash_list_remove(hashtable_t * table,
				     unsigned long hash)
{
	struct hash_list * elem;
	void *data;
	int index;

	index = hash % table->hashtable_size;

	for(elem = &table->table[index]; elem->next != NULL; elem = elem->next) {
		if (elem->next->hash == hash) {
			struct hash_list * hash_data;

			hash_data = elem->next;
			data = hash_data->data;
			elem->next = elem->next->next;

			kfree(hash_data);
			return data;
		}
	}

	return NULL;
}



/** Free a hash table linked list.
 *  @author Viet Hoa Dinh
 *
 *  The function must be called with the lock taken.
 *
 *  @param list  List to free.
 */
static inline void hash_list_free(struct hash_list * list)
{
	struct hash_list * elem;
	struct hash_list * next;

	next = list;
	while (next != NULL) {
		elem = next;
		next = elem->next;
		kfree(elem);
	}
}



/** Find an element in a hash table linked list.
 *  @author Viet Hoa Dinh
 *
 *  The function must be called with the lock taken.
 *
 *  @param head   The linked list to find the element in.
 *  @param hash   The element key.
 *
 *  @return  A pointer to the found data.
 *           NULL if the data is not found.
 */
static inline void * hash_list_find(struct hash_list * head,
				    unsigned long hash)
{
	struct hash_list * elem;

	for(elem = head; elem != NULL; elem = elem->next) {
		if (elem->hash == hash)
			return elem->data;
	}

	return NULL;
}


/** Find an element in a hash table linked list or the next elem in hash order.
 *  @author Renaud Lottiaux
 *
 *  @param head   The linked list to find the element in.
 *  @param hash   The element key.
 *
 *  @return  A pointer to the found data.
 *           NULL if the data is not found.
 *           The hash of the found data is returned in hash_found.
 */
static inline void * hash_list_find_equal_or_next(struct hash_list * head,
						  unsigned long hash,
						  unsigned long *hash_found)
{
	struct hash_list * elem;
	void *found = NULL;

	*hash_found = -1UL;
	for(elem = head; elem != NULL; elem = elem->next) {
		if (elem->hash == hash) {
			*hash_found = elem->hash;
			return elem->data;
		}

		if (elem->hash > hash &&
		    elem->hash <= *hash_found) {
			*hash_found = elem->hash;
			found = elem->data;
		}
	}

	return found;
}


/** Create a new hash table */

hashtable_t *_hashtable_new(unsigned long hashtable_size)
{
	hashtable_t * ht;
	int i;

	ht = kmalloc(sizeof(hashtable_t), GFP_KERNEL);
	if (ht == NULL)
		return NULL;

	ht->table = kmalloc(sizeof(struct hash_list) * hashtable_size,
			    GFP_KERNEL);

	if (ht->table == NULL)
		return NULL;

	ht->hashtable_size = hashtable_size;

	for(i = 0; i < hashtable_size; i++)
		ht->table[i] = HASH_LISTHEAD_NEW;

	return ht;
}
EXPORT_SYMBOL(_hashtable_new);


/** Free a hash table */

void hashtable_free(hashtable_t * table)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave (&table->lock, flags);

	for(i = 0; i < table->hashtable_size; i++)
		hash_list_free(table->table[i].next);

	kfree (table->table);
	spin_unlock_irqrestore (&table->lock, flags);

	kfree(table);
}
EXPORT_SYMBOL(hashtable_free);


/** Add an element in a hash table */

int __hashtable_add(hashtable_t * table,
		    unsigned long hash,
		    void * data)
{
	int index;
	int r = 0;

	index = hash % table->hashtable_size;

	if (table->table[index].data == NULL) {
		table->table[index].hash = hash;
		table->table[index].data = data;
		table->table[index].next = NULL;
	}
	else
		r = hash_list_add(table, hash, data);

	return r;
}
EXPORT_SYMBOL(__hashtable_add);

int __hashtable_add_unique(hashtable_t * table,
			   unsigned long hash,
			   void * data)
{
	int index;
	int r = 0;

	index = hash % table->hashtable_size;

	if (!table->table[index].data) {
		table->table[index].hash = hash;
		table->table[index].data = data;
		table->table[index].next = NULL;
	}
	else if (hash_list_find(&table->table[index], hash))
		r = -EEXIST;
	else
		r = hash_list_add(table, hash, data);

	return r;
}
EXPORT_SYMBOL(__hashtable_add_unique);

/** Remove an element from a hash table */

void *__hashtable_remove(hashtable_t * table,
			 unsigned long hash)
{
	int index;
	struct hash_list * next;
	void *data = NULL;

	index = hash % table->hashtable_size;

	if (table->table[index].hash == hash) {
		data = table->table[index].data;

		if ((next = table->table[index].next) != NULL) {
			table->table[index].hash = next->hash;
			table->table[index].data = next->data;
			table->table[index].next = next->next;
			kfree(next);
		}
		else {
			table->table[index].hash = 0;
			table->table[index].data = NULL;
		}
	}
	else
		data = hash_list_remove(table, hash);

	return data;
}
EXPORT_SYMBOL(__hashtable_remove);


/** Find an element in a hash table */

void * __hashtable_find(hashtable_t * table,
			unsigned long hash)
{
	int index;

	index = hash % table->hashtable_size;

	return hash_list_find(&table->table[index], hash);
}
EXPORT_SYMBOL(__hashtable_find);


/** Find an element in a hash table */

void * __hashtable_find_next(hashtable_t * table,
			     unsigned long hash,
			     unsigned long *hash_found)
{
	unsigned long nearest_possible;
	unsigned long nearest_found, i;
	int index;
	void *found_data = NULL, *data;

	if (hash == -1UL)
		return NULL;

	nearest_found = -1UL;
	nearest_possible = hash + 1;

	for (i = hash + 1; i <= hash + table->hashtable_size; i++) {
		index = i % table->hashtable_size;
		data = hash_list_find_equal_or_next (&table->table[index],
						     i, hash_found);

		if (data && (*hash_found <= nearest_found)) {
			nearest_found = *hash_found;
			found_data = data;

			if (nearest_found == nearest_possible)
				goto done;
		}

		nearest_possible++;
	}

done:
	*hash_found = nearest_found;
	return found_data;
}
EXPORT_SYMBOL(__hashtable_find_next);


/** Apply a function of each hash table key */

void __hashtable_foreach_key(hashtable_t * table,
			     void (* func)(unsigned long, void *),
			     void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			func(cur->hash, data);
			for(elem = cur->next; elem != NULL; elem = elem->next)
				func(elem->hash, data);
		}
	}
}
EXPORT_SYMBOL(__hashtable_foreach_key);


/** Apply a function of each hash table element */

void __hashtable_foreach_data(hashtable_t * table,
			      void (* func)(void *, void *),
			      void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			func(cur->data, data);
			for(elem = cur->next; elem != NULL; elem = elem->next)
				func(elem->data, data);
		}
	}
}
EXPORT_SYMBOL(__hashtable_foreach_data);


/** Apply a function to each hash table pair (key, element) */

void __hashtable_foreach_key_data(hashtable_t * table,
				  void (* func)(unsigned long, void *, void *),
				  void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			func(cur->hash, cur->data, data);
			for(elem = cur->next; elem != NULL; elem = elem->next)
				func(elem->hash, elem->data, data);
		}
	}
}
EXPORT_SYMBOL(__hashtable_foreach_key_data);


void * hashtable_find_data(hashtable_t * table,
			   int (* func)(void *, void *),
			   void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;
	unsigned long flags;
	void * res = NULL;

	spin_lock_irqsave (&table->lock, flags);

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			if (func(cur->data, data)) {
				res = cur->data;
				goto found;
			}
			for(elem = cur->next; elem != NULL; elem = elem->next)
				if (func(elem->data, data)) {
					res = elem->data;
					goto found;
				}
		}
	}

found:
	spin_unlock_irqrestore (&table->lock, flags);
	return res;
}
EXPORT_SYMBOL(hashtable_find_data);
