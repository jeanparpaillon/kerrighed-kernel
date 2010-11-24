#ifndef __HASHED_STRING_LIST_H__
#define __HASHED_STRING_LIST_H__

#include <kddm/kddm_types.h>

struct kddm_set;
struct string_list_object;

struct kddm_set *hashed_string_list_create(kddm_set_id_t kddm_set_id);
int hashed_string_list_remove_local(struct kddm_set *set);

struct string_list_object *
hashed_string_list_lock_hash(struct kddm_set *kddm_set, const char *element);
void hashed_string_list_unlock_hash(struct kddm_set *kddm_set,
				    struct string_list_object *string_list);

#endif /* __HASHED_STRING_LIST_H__ */
