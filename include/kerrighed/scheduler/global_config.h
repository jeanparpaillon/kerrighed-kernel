#ifndef __KRG_SCHEDULER_GLOBAL_CONFIG_H__
#define __KRG_SCHEDULER_GLOBAL_CONFIG_H__

#include <linux/workqueue.h>
#include <linux/list.h>
#include <kerrighed/ghost_types.h>

struct global_config_item;

typedef void global_config_drop_func_t(struct global_config_item *item);

/**
 * Operations associated to a global config item
 */
struct global_config_drop_operations {
	/* callback called when globally dropping a global_config_item */
	global_config_drop_func_t *drop_func;
	/* not null if the item is symbolic link */
	int is_symlink;
};

/**
 * Structure needed to store informations about a global config object
 * (config_item or symlink)
 * Should not be accessed directly.
 */
struct global_config_item {
	struct list_head list;
	struct delayed_work drop_work;
	/* operations associated to the global config item */
	const struct global_config_drop_operations *drop_ops;
	const char *path;
	const char *target_path;
};

/**
 * Block globalized config operations
 *
 * @return		0 if success,
 *			negative error code otherwise
 */
int global_config_freeze(void);
/**
 * Un-block globalized config operations
 */
void global_config_thaw(void);

/**
 * Initialize a global_config_item
 *
 * @param item		item to initialize
 * @param ops		operations associated with this item
 */
void global_config_item_init(struct global_config_item *item,
			     const struct global_config_drop_operations *ops);

struct config_item;
struct string_list_object;

/**
 * Function that prepares a global mkdir
 *
 * @param parent	item under which the operation is done
 * @param name		name of the new sub-directory
 *
 * @return		valid pointer or NULL to be passed to
 *			global_config_make_item_end or
 *			global_config_make_item_error, or error
 */
struct string_list_object *
global_config_make_item_begin(struct config_item *parent, const char *name);
int __global_config_make_item_commit(struct string_list_object *list,
				     struct config_item *parent,
				     struct global_config_item *item,
				     const char *name);
void __global_config_make_item_end(struct string_list_object *list);
/**
 * Commit a global config mkdir
 *
 * @param list		pointer returned by global_config_make_item_begin
 * @param parent	item under which the operation is done
 * @param item		pointer to the global_config_item for the new dir,
 *			previously initialized with global_config_item_init
 * @param name		name of the new dir
 *
 * @return		0 on success, or error
 */
int global_config_make_item_end(struct string_list_object *list,
				struct config_item *parent,
				struct global_config_item *item,
				const char *name);
/**
 * Cleanup a global mkdir if an error occurs before calling
 * global_config_make_item_end
 *
 * @param list		pointer returned by global_config_make_item_begin
 * @param name		name of the new dir
 */
void global_config_make_item_error(struct string_list_object *list,
				   const char *name);

/**
 * Function that prepares a global symlink
 *
 * @param parent	item under which the link is created
 * @param name		name of the new link
 * @param target	target item of the new link
 *
 * @return		valid pointer or NULL to be passed to
 *			global_config_allow_link_end or
 *			global_config_allow_link_error, or error
 */
struct string_list_object *
global_config_allow_link_begin(struct config_item *parent,
			       const char *name,
			       struct config_item *target_name);
int __global_config_allow_link_commit(struct string_list_object *list,
				      struct config_item *parent,
				      struct global_config_item *item,
				      const char *name,
				      struct config_item *target);
void __global_config_allow_link_end(struct string_list_object *list);
/**
 * Commit a global config symlink
 *
 * @param list		pointer returned by global_config_allow_link_begin
 * @param parent	item under which the new link is created
 * @param item		pointer to the global_config_item for the new link,
 *			previously initialized with global_config_item_init
 * @param name		name of the new link
 * @param target	target item of the new link
 *
 * @return		0 on success, or error
 */
int global_config_allow_link_end(struct string_list_object *list,
				      struct config_item *parent,
				      struct global_config_item *item,
				      const char *name,
				      struct config_item *target_name);
/**
 * Cleanup a global symlink if an error occurs before calling
 * global_config_allow_link_end
 *
 * @param list		pointer returned by global_config_allow_link_begin
 * @param name		name of the new link
 * @param target	target item of the new link
 */
void global_config_allow_link_error(struct string_list_object *list,
					 const char *name,
					 struct config_item *target_name);

struct global_config_attrs {
	struct list_head head;
	int valid;
};

struct config_group;

void global_config_attrs_init_r(struct config_group *group);
void global_config_attrs_cleanup_r(struct config_group *group);

struct configfs_attribute;

/**
 * Prepare a global store operation on an attribute.
 *
 * @param item		item owning the attribute
 *
 * @return		a valid pointer or NULL to be passed to
 *			global_config_attr_store_end or
 *			global_config_attr_store_error, or error
 */
struct string_list_object *
global_config_attr_store_begin(struct config_item *item);
/**
 * Commit a global store on an attribute
 *
 * @param list		pointer returned by global_config_attr_store_begin
 * @param item		item owning the attribute
 * @param attr		attribute to modify
 * @param page		buffer containing the value to store
 * @param count		number of bytes to store, as can really be stored
 *			(result from the local store operation for instance).
 *
 * @return		number of bytes written on success, or error
 */
ssize_t global_config_attr_store_end(struct string_list_object *list,
				     struct config_item *item,
				     struct configfs_attribute *attr,
				     const char *page, size_t count);
/**
 * Cleanup a global attribute store if an error occurs before calling
 * global_config_attr_store_end
 *
 * @param list		pointer returned by global_config_attr_store_begin
 * @param item		item owning the attribute
 */
void global_config_attr_store_error(struct string_list_object *list,
				    struct config_item *item);

/**
 * Notify a global rmdir or unlink. The drop may be delayed, so the item should
 * not be freed before the drop callback is called.
 *
 * @param item		global_config_item used for the dropped entry
 */
void global_config_drop(struct global_config_item *item);

struct rpc_desc;
/**
 * Pack information so that a peer config_item can be reached on a peer node.
 *
 * @param desc		RPC descriptor to pack item identification info
 * @param item		local peer item of item to reach on peer nodes
 *
 * @return		0 if successful, or
 *			negative error code
 */
int global_config_pack_item(struct rpc_desc *desc, struct config_item *item);
/**
 * Find and get a reference on the local peer item of a remote item
 *
 * @param desc		RPC descriptor to unpack item identification info
 *
 * @return		Valid pointer to a config_item, or
 *			negative error pointer
 */
struct config_item *global_config_unpack_get_item(struct rpc_desc *desc);

struct epm_action;

/**
 * Export information to a ghost so that a peer config_item can be reached on a
 * peer node
 *
 * @param action	EPM action using the ghost
 * @param ghost		ghost to export to
 * @param item		globalized config_item to reach on peer node
 *
 * @return		0 if successful, or
 *			negative error code
 */
int export_global_config_item(struct epm_action *action, ghost_t *ghost,
			      struct config_item *item);
/**
 * Import information from a ghost and get a reference on a globalized
 * config_item
 * Returns success as long as ghost can still be used. An error in item lookup
 * is returned in item pointer.
 *
 * @param action	EPM action using the ghost
 * @param ghost		ghost to import from
 * @param item_p	pointer to a pointer to fill with the found item or
 *			error item, if ghost info could be successfuly imported
 *
 * @return		0 if ghost import successful, or
 *			negative error code
 */
int import_global_config_item(struct epm_action *action, ghost_t *ghost,
			      struct config_item **item_p);

#endif /* __KRG_SCHEDULER_GLOBAL_CONFIG_H__ */
