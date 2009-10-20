/*
 *  kerrighed/scheduler/string_list.c
 *
 *  Copyright (C) 2007-2008 Louis Rilling - Kerlabs
 *  Copyright (C) 2007 Marko Novak - Xlab
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/types.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>

struct string_list_object {
	struct list_head head;
	unsigned long id;
};

struct string_list_element {
	struct list_head list;
	const void *data;
	size_t size;
	char string[];
};

static struct kmem_cache *string_list_cachep;

static int string_list_alloc_object(struct kddm_obj *obj_entry,
				    struct kddm_set *set,
				    objid_t objid)
{
	struct string_list_object *obj;
	int retval;

	retval = -ENOMEM;
	obj = kmem_cache_alloc(string_list_cachep, GFP_KERNEL);
	if (!obj)
		goto out;
	INIT_LIST_HEAD(&obj->head);
	obj->id = objid;

	obj_entry->object = obj;
	retval = 0;
out:
	return retval;
}

static struct string_list_element *element_alloc(size_t string_length,
						 size_t data_size)
{
	struct string_list_element *elt;
	size_t size = offsetof(typeof(*elt), string) + string_length + 1;

	elt = kmalloc(size, GFP_KERNEL);
	if (!elt)
		goto out;

	elt->size = data_size;
	if (data_size) {
		elt->data = kmalloc(data_size, GFP_KERNEL);
		if (!elt->data) {
			kfree(elt);
			elt = NULL;
		}
	}

out:
	return elt;
}

static void element_free(struct string_list_element *element)
{
	if (element->size)
		kfree(element->data);
	kfree(element);
}

static void string_list_make_empty(struct string_list_object *object)
{
	struct string_list_element *elt, *tmp;

	list_for_each_entry_safe(elt, tmp, &object->head, list) {
		list_del(&elt->list);
		element_free(elt);
	}
}

static int string_list_import_object(struct kddm_obj *obj_entry,
				     struct rpc_desc *desc)
{
	struct string_list_object *obj = obj_entry->object;
	struct string_list_element *elt;
	int nr_elt;
	size_t data_size, len;
	int err;

	string_list_make_empty(obj);

	err = rpc_unpack_type(desc, nr_elt);
	if (err)
		goto out;

	for (; nr_elt > 0; nr_elt--) {
		err = rpc_unpack_type(desc, len);
		if (err)
			break;
		err = rpc_unpack_type(desc, data_size);
		if (err)
			break;

		elt = element_alloc(len, data_size);
		if (!elt) {
			err = -ENOMEM;
			break;
		}

		err = rpc_unpack(desc, 0, elt->string, len + 1);
		if (err)
			goto err_free;

		if (data_size)
			err = rpc_unpack(desc, 0, (void *)elt->data, data_size);
		else
			err = rpc_unpack_type(desc, elt->data);
		if (err)
			goto err_free;

		list_add_tail(&elt->list, &obj->head);
	}

out:
	return err;

err_free:
	element_free(elt);
	goto out;
}

static int string_list_export_object(struct rpc_desc *desc,
				     struct kddm_obj *obj_entry)
{
	struct string_list_object *obj = obj_entry->object;
	struct string_list_element *elt;
	int nr_elt = 0;
	size_t len;
	int err;

	list_for_each_entry(elt, &obj->head, list)
		nr_elt++;
	err = rpc_pack_type(desc, nr_elt);
	if (err)
		goto out;

	list_for_each_entry(elt, &obj->head, list) {
		len = strlen(elt->string);
		err = rpc_pack_type(desc, len);
		if (err)
			break;
		err = rpc_pack_type(desc, elt->size);
		if (err)
			break;

		err = rpc_pack(desc, 0, elt->string, len + 1);
		if (err)
			break;

		if (elt->size)
			err = rpc_pack(desc, 0, elt->data, elt->size);
		else
			err = rpc_pack_type(desc, elt->data);
		if (err)
			break;
	}

out:
	return err;
}

static int string_list_remove_object(void *object,
				     struct kddm_set *set,
				     objid_t objid)
{
	string_list_make_empty(object);
	return 0;
}

static struct iolinker_struct string_list_io_linker = {
	.linker_name   = "string_list",
	.linker_id     = STRING_LIST_LINKER,
	.alloc_object  = string_list_alloc_object,
	.export_object = string_list_export_object,
	.import_object = string_list_import_object,
	.remove_object = string_list_remove_object
};

struct string_list_object *string_list_create_writelock(
	struct kddm_set *kddm_set,
	objid_t objid)
{
	return _kddm_grab_object(kddm_set, objid);
}

struct string_list_object *string_list_writelock(struct kddm_set *kddm_set,
						 objid_t objid)
{
	return _kddm_grab_object_no_ft(kddm_set, objid);
}

void string_list_unlock(struct kddm_set *kddm_set,
			struct string_list_object *object)
{
	_kddm_put_object(kddm_set, object->id);
}

void string_list_unlock_and_destroy(struct kddm_set *kddm_set,
				    struct string_list_object *object)
{
	_kddm_remove_frozen_object(kddm_set, object->id);
}

int string_list_add_element(struct string_list_object *object,
			    const char *element,
			    const void *data, size_t size)
{
	struct string_list_element *elt;

	elt = element_alloc(strlen(element), size);
	if (!elt)
		return -ENOMEM;
	strcpy(elt->string, element);
	if (size)
		memcpy(elt->data, data, size);
	else
		elt->data = data;
	list_add_tail(&elt->list, &object->head);
	return 0;
}

static
struct string_list_element *
string_list_find_element(struct string_list_object *object, const char *element)
{
	struct string_list_element *elt;

	list_for_each_entry(elt, &object->head, list)
		if (!strcmp(element, elt->string))
			return elt;
	return NULL;
}

int string_list_remove_element(struct string_list_object *object,
			       const char *element)
{
	struct string_list_element *elt = string_list_find_element(object,
								   element);

	if (elt) {
		list_del(&elt->list);
		element_free(elt);
		return 0;
	}

	return -ENOENT;
}

int string_list_element_get_data(struct string_list_object *object,
				 const char *element,
				 const void **data, size_t *size)
{
	struct string_list_element *elt;

	elt = string_list_find_element(object, element);
	if (!elt)
		return -ENOENT;

	*data = element->data;
	if (size)
		*size = element->size;
	return 0;
}

int string_list_element_set_data(struct string_list_object *object,
				 const char *element,
				 const void *data, size_t size)
{
	struct string_list_element *elt;
	const void *new_data;

	elt = string_list_find_element(object, element);
	if (!elt)
		return -ENOENT;

	if (size) {
		new_data = kmalloc(size, GFP_KERNEL);
		if (!new_data)
			return -ENOMEM;
		memcpy((void *)new_data, data, size);
	} else {
		new_data = data;
	}

	if (elt->size)
		kfree(elt->data);
	elt->data = new_data;
	elt->size = size;

	return 0;
}

int string_list_is_element(struct string_list_object *object,
			   const char *element)
{
	struct string_list_element *elt = string_list_find_element(object,
								   element);

	return !!elt;
}

int string_list_empty(struct string_list_object *object)
{
	return list_empty(&object->head);
}

int string_list_start(void)
{
	string_list_cachep = KMEM_CACHE(string_list_object, SLAB_PANIC);

	register_io_linker(STRING_LIST_LINKER, &string_list_io_linker);

	return 0;
}

void string_list_exit(void)
{
}
