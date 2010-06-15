/*
 *  kerrighed/scheduler/hashed_string_list.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *  Copyright (C) 2007 Marko Novak - Xlab
 */

#include <linux/string.h>
#include <kddm/kddm.h>

#include "string_list.h"

struct kddm_set *hashed_string_list_create(kddm_set_id_t kddm_set_id)
{
	return create_new_kddm_set(kddm_def_ns, kddm_set_id,
				   STRING_LIST_LINKER,
				   KDDM_RR_DEF_OWNER,
				   0,
				   KDDM_LOCAL_EXCLUSIVE);
}

static unsigned long get_hash(const char *string)
{
	unsigned long hash = 0;
	const char *limit = string + strlen(string) - sizeof(hash);
	const unsigned long *pos;

	for (pos = (const unsigned long *) string; (char *) pos <= limit; pos++)
		hash = hash ^ *pos;

	if ((char *) (pos - 1) < limit) {
		unsigned long last_hash = 0;

		strcpy((char *) &last_hash, (const char *) pos);
		hash = hash ^ last_hash;
	}

	return hash;
}

struct string_list_object *
hashed_string_list_lock_hash(struct kddm_set *kddm_set, const char *element)
{
	return string_list_create_writelock(kddm_set, get_hash(element));
}

void hashed_string_list_unlock_hash(struct kddm_set *kddm_set,
				    struct string_list_object *string_list)
{
	if (string_list_empty(string_list))
		string_list_unlock_and_destroy(kddm_set, string_list);
	else
		string_list_unlock(kddm_set, string_list);
}

static int hashed_string_list_flusher(struct kddm_set *set, objid_t objid,
				      struct kddm_obj *obj_entry, void *data)
{
	return nth_online_krgnode(objid % num_online_krgnodes());
}

int hashed_string_list_remove_local(struct kddm_set *set)
{
	if (num_online_krgnodes())
		_kddm_flush_set(set, hashed_string_list_flusher, NULL);
	return 0;
}
