/** Application management of struct(s) shared by several processes
 *
 * The following definitions help to understand the code
 * - shared: an object that *can* be linked to several processes
 * - dist(ributed): an object that *is* linked to several processes on
 *                  different nodes
 * - local: an object that is *not distributed*. the object *may* be linked
 *          to severall processes, but in that case, they are all on
 *          the *same* node
 *
 *
 *  Copyright (C) 2007-2008 Matthieu Fertré - INRIA
 */

#include <linux/file.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/unique_id.h>
#include <linux/nsproxy.h>
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <linux/pid_namespace.h>
#include <net/net_namespace.h>
#include <kerrighed/faf.h>
#include <kerrighed/faf_file_mgr.h>
#include <kerrighed/file.h>
#include <kerrighed/namespace.h>
#include <kerrighed/regular_file_mgr.h>
#include <kerrighed/task.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kerrighed/application.h>
#include <kerrighed/ghost_helpers.h>
#include <kerrighed/app_shared.h>
#include <kerrighed/ghost_helpers.h>
#include "../epm_internal.h"
#include "app_utils.h"

/*--------------------------------------------------------------------------*/

extern struct shared_object_operations cr_shared_pipe_inode_ops;
extern struct shared_object_operations cr_shared_file_ops;
extern struct shared_object_operations cr_shared_unsupported_file_ops;
extern struct shared_object_operations cr_shared_files_struct_ops;
extern struct shared_object_operations cr_shared_fs_struct_ops;
#ifdef CONFIG_KRG_MM
extern struct shared_object_operations cr_shared_mm_struct_ops;
#endif
extern struct shared_object_operations cr_shared_semundo_ops;
extern struct shared_object_operations cr_shared_sighand_struct_ops;
extern struct shared_object_operations cr_shared_signal_struct_ops;

static struct shared_object_operations * get_shared_ops(
	enum shared_obj_type type)
{
	struct shared_object_operations * s_ops = NULL;

	switch (type) {
	case PIPE_INODE:
		s_ops = &cr_shared_pipe_inode_ops;
		break;
	case LOCAL_FILE:
	case DVFS_FILE:
		s_ops = &cr_shared_file_ops;
		break;
	case FILES_STRUCT:
		s_ops = &cr_shared_files_struct_ops;
		break;
	case FS_STRUCT:
		s_ops = &cr_shared_fs_struct_ops;
		break;
#ifdef CONFIG_KRG_MM
	case MM_STRUCT:
		s_ops = &cr_shared_mm_struct_ops;
		break;
#endif
	case SEMUNDO_LIST:
		s_ops = &cr_shared_semundo_ops;
		break;
	case SIGHAND_STRUCT:
		s_ops = &cr_shared_sighand_struct_ops;
		break;
	case SIGNAL_STRUCT:
		s_ops = &cr_shared_signal_struct_ops;
		break;
	default:
		BUG();
		break;
	}
	return s_ops;
}

/*--------------------------------------------------------------------------*/

struct shared_index {
	struct rb_node node;

	enum shared_obj_type type;
	unsigned long key;
};

static struct rb_node * search_node(struct rb_root *root,
				    enum shared_obj_type type,
				    unsigned long key)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct shared_index *idx =
			container_of(node, struct shared_index, node);
		int result;

		result = type - idx->type;

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			result = key - idx->key;
			if (result < 0)
				node = node->rb_left;
			else if (result > 0)
				node = node->rb_right;
			else
				return node;
		}
	}
	return NULL;
}

static struct shared_index *search_shared_index(struct rb_root *root,
						enum shared_obj_type type,
						unsigned long key)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct shared_index *idx;
		int result;

		idx = container_of(node, struct shared_index, node);
		result = type - idx->type;

		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
			result = key - idx->key;
			if (result < 0)
				node = node->rb_left;
			else if (result > 0)
				node = node->rb_right;
			else
				return idx;
		}
	}
	return NULL;
}

static struct shared_index *__insert_shared_index(struct rb_root *root,
						  struct shared_index *idx)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

	/* Figure out where to put new node */
	while (*new) {
		struct shared_index *this =
			container_of(*new, struct shared_index, node);

		int result = idx->type - this->type;

		parent = *new;
		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else {
			result = idx->key - this->key;
			if (result < 0)
				new = &((*new)->rb_left);
			else if (result > 0)
				new = &((*new)->rb_right);
			else
				return this;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&idx->node, parent, new);
	rb_insert_color(&idx->node, root);

	return idx;
}

static int insert_shared_index(struct rb_root *root, struct shared_index *idx)
{
	struct shared_index *idx2;
	idx2 = __insert_shared_index(root, idx);
	if (idx2 == idx)
		return 0;

	return -ENOKEY;
}

/*--------------------------------------------------------------------------*/

struct shared_object {
	struct shared_index index;
	struct shared_object_operations *ops;

	union {
		struct {
			struct export_obj_info export;
			enum object_locality locality;
		} checkpoint;
		struct {
			/* SHARED_ANY must not be used at restart */
			enum object_locality locality;

			void *data;
			size_t data_size;
		} restart;
	};
};

static struct shared_object *search_shared_object(struct rb_root *root,
						  enum shared_obj_type type,
						  unsigned long key)
{
	struct shared_object *data = NULL;
	struct shared_index *idx = search_shared_index(root, type, key);

	if (!idx)
		goto out;

	data = container_of(idx, struct shared_object, index);

out:
	return data;
}

void * get_imported_shared_object(struct app_struct *app,
				  enum shared_obj_type type,
				  unsigned long key)
{
	void *data = NULL;
	struct shared_object *s;

	spin_lock(&app->shared_objects.lock);
	s = search_shared_object(&app->shared_objects.root, type, key);
	if (s)
		data = s->restart.data;
	spin_unlock(&app->shared_objects.lock);

	return data;
}

/* to use only at checkpoint time! */
int add_to_shared_objects_list(struct app_struct *app,
			       enum shared_obj_type type,
			       unsigned long key,
			       enum object_locality locality,
			       struct task_struct *exporting_task,
			       union export_args *args,
			       int force)
{
	int r;
	struct shared_object_operations *s_ops;
	struct shared_object *s;

	s_ops = get_shared_ops(type);
	s = kmalloc(sizeof(struct shared_object), GFP_KERNEL);

	if (!s)
		return -ENOMEM;

	s->index.type = type;
	s->index.key = key;

	spin_lock(&app->shared_objects.lock);

	r = insert_shared_index(&app->shared_objects.root, &s->index);
	if (r) {
		/* shared object is already in the list */
		kfree(s);

		/* we should record additionnal info about exporting task */
		if (force) {
			struct export_obj_info *export;

			s = search_shared_object(&app->shared_objects.root,
						 type, key);
			BUG_ON(!s);

			export = kmalloc(sizeof(struct export_obj_info),
					 GFP_KERNEL);
			if (!export) {
				kfree(s);
				goto err_unlock;
			}

			export->task = exporting_task;
			if (args)
				export->args = *args;
			list_add_tail(&export->next,
				      &s->checkpoint.export.next);
			r = 0;
		}
#ifdef CONFIG_KRG_DEBUG
		else {
			s = search_shared_object(&app->shared_objects.root,
						 type, key);
			BUG_ON(!s);
		}
#endif
	} else {
		/* the object was not in the list, finishing initialization */
		s->ops = s_ops;

		s->checkpoint.export.task = exporting_task;
		if (args)
			s->checkpoint.export.args = *args;
		INIT_LIST_HEAD(&s->checkpoint.export.next);

		s->checkpoint.locality = locality;
	}
err_unlock:
	spin_unlock(&app->shared_objects.lock);

	return r;
}

static void clear_one_shared_object(struct rb_node *node,
				    struct app_struct *app)
{
	struct shared_index *idx =
		container_of(node, struct shared_index, node);

	struct shared_object *this =
		container_of(idx, struct shared_object, index);

	struct list_head *tmp, *element;
	struct export_obj_info *export;

	/* this is called only after checkpoint, we can safely do that */
	list_for_each_safe(element, tmp, &this->checkpoint.export.next) {
		export = list_entry(element, struct export_obj_info, next);
		list_del(element);
		kfree(export);
	}

	rb_erase(node, &app->shared_objects.root);
	kfree(this);
}

void clear_shared_objects(struct app_struct *app)
{
	struct rb_node *node;

	while ((node = rb_first(&app->shared_objects.root)))
		clear_one_shared_object(node, app);
}

struct task_struct *alloc_shared_fake_task_struct(struct app_struct *app)
{
	struct task_struct *fake;
	struct krg_namespace *krg_ns;

	fake = alloc_task_struct();
	if (!fake) {
		fake = ERR_PTR(-ENOMEM);
		goto exit;
	}

	fake->nsproxy = kmem_cache_alloc(nsproxy_cachep, GFP_KERNEL);
	if (!fake->nsproxy) {
		fake = ERR_PTR(-ENOMEM);
		goto exit;
	}

	krg_ns = find_get_krg_ns();
	if (!krg_ns) {
		fake = ERR_PTR(-EPERM);
		goto err_ns;
	}

	fake->pid = 0;

	get_uts_ns(krg_ns->root_nsproxy.uts_ns);
	fake->nsproxy->uts_ns = krg_ns->root_nsproxy.uts_ns;
	get_ipc_ns(krg_ns->root_nsproxy.ipc_ns);
	fake->nsproxy->ipc_ns = krg_ns->root_nsproxy.ipc_ns;
	get_mnt_ns(krg_ns->root_nsproxy.mnt_ns);
	fake->nsproxy->mnt_ns = krg_ns->root_nsproxy.mnt_ns;
	get_pid_ns(krg_ns->root_nsproxy.pid_ns);
	fake->nsproxy->pid_ns = krg_ns->root_nsproxy.pid_ns;
	get_net(krg_ns->root_nsproxy.net_ns);
	fake->nsproxy->net_ns = krg_ns->root_nsproxy.net_ns;

	fake->nsproxy->krg_ns = krg_ns;

	fake->application = app;

exit:
	return fake;
err_ns:
	kmem_cache_free(nsproxy_cachep, fake->nsproxy);
	goto exit;
}

void free_shared_fake_task_struct(struct task_struct *fake)
{
	free_nsproxy(fake->nsproxy);

	free_task_struct(fake);
}

static inline void reset_fake_task_struct(struct task_struct *fake)
{
	struct nsproxy *ns;
	struct app_struct *app;

	ns = fake->nsproxy;
	app = fake->application;

	memset(fake, 0, sizeof(struct task_struct));

	fake->nsproxy = ns;
	fake->application = app;
	spin_lock_init(&fake->alloc_lock);
}

static void destroy_one_shared_object(struct rb_node *node,
				      struct app_struct *app,
				      struct task_struct *fake)
{
	struct shared_index *idx =
		container_of(node, struct shared_index, node);

	struct shared_object *this =
		container_of(idx, struct shared_object, index);

	rb_erase(node, &app->shared_objects.root);
	this->ops->delete(fake, this->restart.data);

	kfree(this);
}

void destroy_shared_objects(struct app_struct *app,
			    struct task_struct *fake)
{
	struct rb_node *node;

	reset_fake_task_struct(fake);

	while ((node = rb_first(&app->shared_objects.root)))
		destroy_one_shared_object(node, app, fake);
}

/*--------------------------------------------------------------------------*/

static int __export_one_shared_object_kernel(struct epm_action *action,
					     ghost_t *ghost,
					     struct shared_object *this)
{
	int r = 0;

	if (this->checkpoint.locality != SHARED_MASTER
	    && this->checkpoint.locality != LOCAL_ONLY)
		/* nothing to do, we are not responsible of this object */
		goto error;

	r = ghost_write(ghost, &this->index.type,
			sizeof(enum shared_obj_type));
	if (r)
		goto error;
	r = ghost_write(ghost, &this->index.key, sizeof(long));
	if (r)
		goto error;

	r = ghost_write(ghost, &this->checkpoint.locality,
			sizeof(enum object_locality));
	if (r)
		goto error;

	r = this->ops->export_now(action, ghost,
				  this->checkpoint.export.task,
				  &this->checkpoint.export.args);

error:
	return r;
}

static int export_one_shared_object(struct epm_action *action,
				    ghost_t *ghost,
				    ghost_t *user_ghost,
				    struct shared_object *this)
{
	int r;

	BUG_ON(!this->ops->export_user_info &&
	       this->checkpoint.locality == SHARED_SLAVE);
	BUG_ON(this->checkpoint.locality != LOCAL_ONLY
	       && this->checkpoint.locality != SHARED_MASTER
	       && this->checkpoint.locality != SHARED_SLAVE);

	r = __export_one_shared_object_kernel(action, ghost, this);
	if (r)
		goto error;

	if (this->ops->export_user_info)
		r = this->ops->export_user_info(action, user_ghost,
						this->index.key,
						&this->checkpoint.export);

error:
	if (r)
		epm_error(action, r, this->checkpoint.export.task,
			  "Fail to save object of type: %u and key: %lu",
			  this->index.type, this->index.key);

	return r;
}

static int export_shared_objects(struct epm_action *action,
				 ghost_t *ghost,
				 ghost_t *user_ghost,
				 struct app_struct *app,
				 enum shared_obj_type from,
				 enum shared_obj_type to)
{
	int r = 0;
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node, *next_node;

	node = rb_first(&app->shared_objects.root);
	while (node) {
		struct shared_index *idx;
		struct shared_object *this;

		next_node = rb_next(node);

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct shared_object, index);

		if (idx->type < from)
			goto next_node;

		if (idx->type > to)
			goto exit_write_end;

		r = export_one_shared_object(action, ghost, user_ghost, this);
		clear_one_shared_object(node, app);

		if (r)
			goto error;

	next_node:
		node = next_node;
	}

exit_write_end:
	r = ghost_write(ghost, &end,
			sizeof(enum shared_obj_type));
error:
	return r;
}

static int chkpt_shared_objects(struct app_struct *app, int chkpt_sn)
{
	int r, err;
	struct epm_action action;
	ghost_fs_t oldfs;
	ghost_t *ghost, *user_ghost;

	action.type = EPM_CHECKPOINT;
	action.checkpoint.appid = app->app_id;
	action.checkpoint.shared = CR_SAVE_NOW;

	__set_ghost_fs(&oldfs);

	ghost = create_file_ghost(GHOST_WRITE, app->app_id, chkpt_sn,
				  "shared_obj_%d.bin", kerrighed_node_id);

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		epm_error(&action, r, NULL,
			  "Fail to create file "
			  "/var/chkpt/%ld/v%d/shared_obj_%u.bin",
			  app->app_id, chkpt_sn, kerrighed_node_id);
		goto exit_unset_fs;
	}

	user_ghost = create_file_ghost(GHOST_WRITE, app->app_id, chkpt_sn,
				       "user_info_%u.txt", kerrighed_node_id);

	if (IS_ERR(user_ghost)) {
		r = PTR_ERR(user_ghost);
		epm_error(&action, r, NULL,
			  "Fail to create file "
			  "/var/chkpt/%ld/v%d/%s/user_info_%u.txt",
			  app->app_id, chkpt_sn, kerrighed_node_id);
		goto exit_close_ghost;
	}

	r = export_shared_objects(&action, ghost, user_ghost, app,
				  PIPE_INODE, DVFS_FILE);
	if (r)
		goto exit_close_user_ghost;

	r = export_shared_objects(&action, ghost, user_ghost, app,
				  FILES_STRUCT, SIGNAL_STRUCT);

exit_close_user_ghost:
	err = ghost_close(user_ghost);
	if (!r)
		r = err;

exit_close_ghost:
	/* End of the really interesting part */
	err = ghost_close(ghost);
	if (!r)
		r = err;

exit_unset_fs:
	unset_ghost_fs(&oldfs);

	return r;
}

/*--------------------------------------------------------------------------*/

static int send_dist_objects_list(struct rpc_desc *desc,
				  struct app_struct *app)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(&app->shared_objects.root);
	     node ; node = rb_next(node) ) {
		struct shared_index *idx;
		struct shared_object *this;
		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct shared_object, index);

		if (this->checkpoint.locality != LOCAL_ONLY) {
			r = rpc_pack_type(desc, idx->type);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, idx->key);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, this->checkpoint.locality);
			if (r)
				goto err_pack;
		}
	}
	r = rpc_pack_type(desc, end);

err_pack:
	return r;
}

struct dist_shared_index {
	struct shared_index index;
	kerrighed_node_t master_node;
	krgnodemask_t nodes;
};

static void clear_one_dist_shared_index(struct rb_node *node,
					struct rb_root *dist_shared_indexes)
{
	struct shared_index *idx =
		container_of(node, struct shared_index, node);

	struct dist_shared_index *this =
		container_of(idx, struct dist_shared_index, index);

	rb_erase(node, dist_shared_indexes);
	kfree(this);
}

static void clear_dist_shared_indexes(struct rb_root *dist_shared_indexes)
{
	struct rb_node *node;

	while ((node = rb_first(dist_shared_indexes)))
		clear_one_dist_shared_index(node, dist_shared_indexes);
}

static int rcv_dist_objects_list_from(struct rpc_desc *desc,
				      struct rb_root *dist_shared_indexes,
				      kerrighed_node_t node)
{
	int r;
	enum shared_obj_type type;

	r = rpc_unpack_type_from(desc, node, type);
	if (r)
		goto error;

	while (type != NO_OBJ) {
		struct dist_shared_index *s;
		struct shared_index *idx;
		unsigned long key;
		enum object_locality locality = LOCAL_ONLY;

		r = rpc_unpack_type_from(desc, node, key);
		if (r)
			goto error;

		r = rpc_unpack_type_from(desc, node, locality);
		if (r)
			goto error;

		s = kmalloc(sizeof(struct dist_shared_index), GFP_KERNEL);
		if (!s) {
			r = -ENOMEM;
			goto error;
		}

		s->index.type = type;
		s->index.key = key;
		s->master_node = KERRIGHED_NODE_ID_NONE;
		krgnodes_clear(s->nodes);

		idx = __insert_shared_index(dist_shared_indexes, &s->index);
		if (idx != &s->index) {
			kfree(s);
			s = container_of(idx, struct dist_shared_index, index);
		}

		BUG_ON(locality == LOCAL_ONLY);

		if (s->master_node == KERRIGHED_NODE_ID_NONE) {
			if (locality == SHARED_MASTER
			    || locality == SHARED_ANY)
				s->master_node = node;
		} else
			/* only one master per object */
			BUG_ON(locality == SHARED_MASTER);

		krgnode_set(node, s->nodes);

		/* next ! */
		r = rpc_unpack_type_from(desc, node, type);
		if (r)
			goto error;
	}

error:
	return r;
}

static int send_full_dist_objects_list(struct rpc_desc *desc,
				       struct rb_root *dist_shared_indexes)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(dist_shared_indexes);
	     node ; node = rb_next(node) ) {
		struct dist_shared_index *this;
		struct shared_index *idx;

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct dist_shared_index, index);

		if (this->master_node == KERRIGHED_NODE_ID_NONE) {
			/* the master node for this object is
			 * not implied in the checkpoint
			 */
			r = -ENOSYS;
			goto err;
		}

		r = rpc_pack_type(desc, idx->type);
		if (r)
			goto err;

		r = rpc_pack_type(desc, idx->key);
		if (r)
			goto err;

		r = rpc_pack_type(desc, this->master_node);
		if (r)
			goto err;

		r = rpc_pack_type(desc, this->nodes);
		if (r)
			goto err;
	}
	r = rpc_pack_type(desc, end);

err:
	return r;
}


static int rcv_full_dist_objects_list(struct rpc_desc *desc,
				      struct app_struct *app)

{
	int r;
	struct rb_node *node;
	struct dist_shared_index s;

	r = rpc_unpack_type(desc, s.index.type);
	if (r)
		goto error;

	while (s.index.type != NO_OBJ) {

		r = rpc_unpack_type(desc, s.index.key);
		if (r)
			goto error;

		r = rpc_unpack_type(desc, s.master_node);
		if (r)
			goto error;

		r = rpc_unpack_type(desc, s.nodes);
		if (r)
			goto error;

		node = search_node(&app->shared_objects.root,
				   s.index.type, s.index.key);

		if (node) {
			struct shared_index *idx;
			struct shared_object *obj;

			idx = container_of(node, struct shared_index, node);
			obj = container_of(idx, struct shared_object, index);

			if (krgnode_is_unique(kerrighed_node_id, s.nodes))
				obj->checkpoint.locality = LOCAL_ONLY;
			else if (s.master_node == kerrighed_node_id)
				obj->checkpoint.locality = SHARED_MASTER;
			else if (obj->ops->export_user_info)
				obj->checkpoint.locality = SHARED_SLAVE;
			else
				clear_one_shared_object(node, app);
		}

		/* next ! */
		r = rpc_unpack_type(desc, s.index.type);
		if (r)
			goto error;
	}

error:
	return r;
}

int local_chkpt_shared(struct rpc_desc *desc,
		       struct app_struct *app,
		       int chkpt_sn)
{
	int r = 0;

	/* 1) send list of distributed objects */
	r = send_dist_objects_list(desc, app);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* 2) receive the list of which node should dump
	 * which distributed object */
	r = rcv_full_dist_objects_list(desc, app);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* 4) dump the shared objects for which we are responsible */
	r = chkpt_shared_objects(app, chkpt_sn);
error:
	return r;
}

int global_chkpt_shared(struct rpc_desc *desc,
			struct app_kddm_object *obj)
{
	int r = 0;
	kerrighed_node_t node;
	struct rb_root dist_shared_indexes = RB_ROOT;

	/* 1) waiting the list of shared objects */

	for_each_krgnode_mask(node, obj->nodes) {
		r = rcv_dist_objects_list_from(desc,
					       &dist_shared_indexes,
					       node);
		if (r)
			goto err_clear_shared;
	}

	/* is it really ok */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto err_clear_shared;

	/* 2) send the list to every node
	 * this is not optimized but otherwise, we need to open
	 * a new RPC desc to each node */

	/* go ahead, nodes should prepare to receive the list */
	r = rpc_pack_type(desc, r);
	if (r)
		goto err_clear_shared;

	r = send_full_dist_objects_list(desc, &dist_shared_indexes);
	if (r)
		goto err_clear_shared;

	/* waiting results from the nodes hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto err_clear_shared;

	/* 4) request them to dump the shared obj */
	r = ask_nodes_to_continue(desc, obj->nodes, r);

err_clear_shared:
	clear_dist_shared_indexes(&dist_shared_indexes);
	return r;
}

/*--------------------------------------------------------------------------*/


static int import_one_shared_object(struct epm_action *action, ghost_t *ghost,
				    struct task_struct *fake,
				    enum shared_obj_type type)
{
	int r;
	struct shared_object_operations *s_ops;
	struct shared_object stmp, *s;
	int is_local;

	s_ops = get_shared_ops(type);

	BUG_ON(type == NO_OBJ);

	stmp.index.type = type;
	stmp.index.key = 0;
	stmp.ops = s_ops;
	stmp.restart.data = NULL;
	stmp.restart.data_size = 0;

	r = ghost_read(ghost, &stmp.index.key, sizeof(long));
	if (r)
		goto err;

	r = ghost_read(ghost, &stmp.restart.locality,
		       sizeof(enum object_locality));
	if (r)
		goto err;

	if (stmp.restart.locality == LOCAL_ONLY)
		is_local = 1;
	else {
		BUG_ON(stmp.restart.locality != SHARED_MASTER);
		is_local = 0;
	}

	/* Look for already imported object.
	 *
	 * It can occur with files replaced at restart time
	 */
	s = search_shared_object(&fake->application->shared_objects.root,
				 stmp.index.type, stmp.index.key);
	if (s) {
		stmp.restart.data = s->restart.data;
		stmp.restart.data_size = s->restart.data_size;
	}

	/* if stmp.restart.data != NULL, data must be read from the ghost
	 * but object must not be imported
	 */
	r = s_ops->import_now(action, ghost, fake, is_local,
			      &stmp.restart.data,
			      &stmp.restart.data_size);
	if (r || s)
		goto err;

	s = kmalloc(sizeof(struct shared_object) + stmp.restart.data_size,
		    GFP_KERNEL);
	if (!s) {
		r = -ENOMEM;
		goto err;
	}

	*s = stmp;
	if (stmp.restart.data_size) {
		s->restart.data = &s[1];
		memcpy(s->restart.data, stmp.restart.data,s->restart.data_size);
	}

	r = insert_shared_index(&fake->application->shared_objects.root,
				&s->index);
	if (r)
		kfree(s);
err:
	if (r)
		epm_error(action, r, fake,
			  "Fail to restore object of type: %u and key: %lu",
			  type, stmp.index.key);
	return r;
}

static int import_shared_objects(struct epm_action *action, ghost_t *ghost,
				 struct task_struct *fake)
{
	int r;
	enum shared_obj_type type = NO_OBJ;

	r = ghost_read(ghost, &type, sizeof(enum shared_obj_type));
	if (r)
		goto error;

	reset_fake_task_struct(fake);

	while (type != NO_OBJ) {

		r = import_one_shared_object(action, ghost, fake, type);
		if (r)
			goto error;

		r = ghost_read(ghost, &type, sizeof(enum shared_obj_type));
		if (r)
			goto error;
	}

error:
	return r;
}

static int send_restored_objects(struct rpc_desc *desc, struct app_struct *app,
				 enum shared_obj_type from,
				 enum shared_obj_type to)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(&app->shared_objects.root);
	     node ; node = rb_next(node) ) {

		struct shared_object *this;
		struct shared_index *idx;

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct shared_object, index);

		BUG_ON(this->restart.locality == SHARED_ANY);

		if (this->restart.locality == SHARED_MASTER &&
		    (idx->type >= from && idx->type <= to)) {
			r = rpc_pack_type(desc, idx->type);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, idx->key);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, this->restart.data_size);
			if (r)
				goto err_pack;

			if (this->restart.data_size)
				r = rpc_pack(desc, 0, this->restart.data,
					     this->restart.data_size);
			else
				r = rpc_pack_type(desc, this->restart.data);
			if (r)
				goto err_pack;
		}
	}
	r = rpc_pack_type(desc, end);

err_pack:
	return r;
}

struct restored_dist_shared_index {
	struct shared_index index;
	size_t data_size;
	void *data;
};

static void clear_one_restored_dist_shared_index(
	struct rb_node *node,
	struct rb_root *dist_shared_indexes)
{
	struct shared_index *idx =
		container_of(node, struct shared_index, node);

	struct restored_dist_shared_index *this =
		container_of(idx, struct restored_dist_shared_index, index);

	rb_erase(node, dist_shared_indexes);
	kfree(this);
}

static void clear_restored_dist_shared_indexes(
	struct rb_root *dist_shared_indexes)
{
	struct rb_node *node;

	while ((node = rb_first(dist_shared_indexes)))
		clear_one_restored_dist_shared_index(node, dist_shared_indexes);
}

static int rcv_restored_dist_objects_list_from(
	struct rpc_desc *desc,
	struct rb_root *dist_shared_indexes,
	kerrighed_node_t node)
{
	int r;
	enum shared_obj_type type;

	r = rpc_unpack_type_from(desc, node, type);
	if (r)
		goto error;

	while (type != NO_OBJ) {
		struct restored_dist_shared_index *s;
		unsigned long key;
		void *data;
		size_t data_size;

		r = rpc_unpack_type_from(desc, node, key);
		if (r)
			goto error;

		r = rpc_unpack_type_from(desc, node, data_size);
		if (r)
			goto error;

		s = kmalloc(sizeof(struct restored_dist_shared_index)
			    + data_size, GFP_KERNEL);
		if (!s) {
			r = -ENOMEM;
			goto error;
		}

		s->index.type = type;
		s->index.key = key;
		s->data_size = data_size;

		if (data_size) {
			data = &s[1];
			r = rpc_unpack_from(desc, node, 0, data, data_size);
		} else
			r = rpc_unpack_type_from(desc, node, data);

		if (r) {
			kfree(s);
			goto error;
		}

		s->data = data;

		r = insert_shared_index(dist_shared_indexes, &s->index);
		if (r) {
			kfree(s);
			s = NULL;
		}

		/* next ! */
		r = rpc_unpack_type_from(desc, node, type);
		if (r)
			goto error;
	}

error:
	return r;
}

static int send_full_restored_dist_objects_list(
	struct rpc_desc *desc,
	struct rb_root *dist_shared_indexes)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(dist_shared_indexes);
	     node ; node = rb_next(node) ) {
		struct restored_dist_shared_index *this;
		struct shared_index *idx;

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct restored_dist_shared_index,
				    index);

		r = rpc_pack_type(desc, idx->type);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, idx->key);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, this->data_size);
		if (r)
			goto err_pack;

		if (this->data_size)
			r = rpc_pack(desc, 0, this->data,
				     this->data_size);
		else
			r = rpc_pack_type(desc, this->data);

		if (r)
			goto err_pack;
	}
	r = rpc_pack_type(desc, end);

err_pack:
	return r;
}

static int rcv_full_restored_objects(
	struct rpc_desc *desc,
	struct app_struct *app)
{
	int r;
	struct restored_dist_shared_index s;

	r = rpc_unpack_type(desc, s.index.type);
	if (r)
		goto error;

	while (s.index.type != NO_OBJ) {
		struct shared_object *obj;

		r = rpc_unpack_type(desc, s.index.key);
		if (r)
			goto error;

		r = rpc_unpack_type(desc, s.data_size);
		if (r)
			goto error;

		obj = kmalloc(sizeof(struct shared_object) + s.data_size,
			      GFP_KERNEL);

		if (!obj) {
			r = -ENOMEM;
			goto error;
		}

		obj->index.type = s.index.type;
		obj->index.key = s.index.key;

		if (s.data_size) {
			s.data = &obj[1];
			r = rpc_unpack(desc, 0, s.data, s.data_size);
		}
		else
			r = rpc_unpack_type(desc, s.data);

		if (r) {
			kfree(obj);
			goto error;
		}

		obj->restart.locality = SHARED_SLAVE;
		obj->restart.data = s.data;
		obj->ops = get_shared_ops(obj->index.type);

		/* try to add it */
		r = insert_shared_index(&app->shared_objects.root, &obj->index);
		if (r)
			kfree(obj);

		/* next ! */
		r = rpc_unpack_type(desc, s.index.type);
		if (r)
			goto error;
	}

error:
	return r;
}

/*--------------------------------------------------------------------------*/

struct substitution_file {
	struct shared_index index;
	kerrighed_node_t node;
	size_t data_size;
	void *data;
	struct file *file;
};

static void clear_one_substitution_file(struct rb_node *node,
					struct rb_root *files)
{
	struct shared_index *idx =
		container_of(node, struct shared_index, node);

	struct substitution_file *this =
		container_of(idx, struct substitution_file, index);

	rb_erase(node, files);

	if (this->data_size)
		kfree(this->data);

	fput(this->file);

	kfree(this);
}

static void clear_substitution_files(struct rb_root *files)
{
	struct rb_node *node;

	while ((node = rb_first(files)))
		clear_one_substitution_file(node, files);
}

static int send_substitution_files(struct rpc_desc *desc,
				   struct rb_root *substitution_files)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(substitution_files);
	     node ; node = rb_next(node)) {
		struct substitution_file *this;
		struct shared_index *idx;

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct substitution_file, index);

		r = rpc_pack_type(desc, idx->type);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, idx->key);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, this->node);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, this->data_size);
		if (r)
			goto err_pack;

		if (this->data_size)
			r = rpc_pack(desc, 0, this->data,
				     this->data_size);
		else
			r = rpc_pack_type(desc, this->data);

		if (r)
			goto err_pack;
	}
	r = rpc_pack_type(desc, end);

err_pack:
	return r;
}

static int rcv_substitution_files(struct rpc_desc *desc,
				  struct app_struct *app)
{
	int r;
	struct shared_index index;
	kerrighed_node_t node;
	size_t data_size;
	void *data;

	r = rpc_unpack_type(desc, index.type);
	if (r)
		goto error;

	while (index.type != NO_OBJ) {
		struct shared_object *obj;

		if (index.type != DVFS_FILE
		    && index.type != LOCAL_FILE) {
			r = -EINVAL;
			goto error;
		}

		r = rpc_unpack_type(desc, index.key);
		if (r)
			goto error;

		r = rpc_unpack_type(desc, node);
		if (r)
			goto error;

		r = rpc_unpack_type(desc, data_size);
		if (r)
			goto error;

		obj = kmalloc(sizeof(struct shared_object) + data_size,
			      GFP_KERNEL);

		if (!obj) {
			r = -ENOMEM;
			goto error;
		}

		if (data_size) {
			data = &obj[1];
			r = rpc_unpack(desc, 0, data, data_size);
		}
		else
			r = rpc_unpack_type(desc, data);

		if (r) {
			kfree(obj);
			goto error;
		}

		if (node == KERRIGHED_NODE_ID_NONE
		    || krgnode_isset(node, app->restart.replacing_nodes)) {

			/* the object is useful on this node, add it */
			obj->index.type = index.type;
			obj->index.key = index.key;

			obj->restart.locality = SHARED_SLAVE;
			obj->restart.data = data;
			obj->ops = get_shared_ops(obj->index.type);

			/* try to add it */
			r = insert_shared_index(&app->shared_objects.root,
						&obj->index);
			if (r) {
				kfree(obj);
				goto error;
			}
		} else
			/* object is useless here
			 * one day, with a good implementation of rpc_pack_to,
			 * this code path may disappear
			 */
			kfree(obj);

		/* next ! */
		r = rpc_unpack_type(desc, index.type);
		if (r)
			goto error;
	}

error:
	return r;
}

static int __insert_one_substitution_file(struct rb_root *files,
					  enum shared_obj_type type,
					  unsigned long key,
					  kerrighed_node_t node,
					  size_t data_size,
					  void *data,
					  struct file *file)
{
	int r;
	struct shared_index *idx;
	struct substitution_file *obj;

	obj = kmalloc(sizeof(struct substitution_file), GFP_KERNEL);
	if (!obj) {
		r = -ENOMEM;
		goto error;
	}

	obj->index.type = type;
	obj->index.key = key;
	obj->node = node;
	obj->data_size = data_size;
	obj->data = data;
	obj->file = file;

	idx = __insert_shared_index(files, &obj->index);
	if (idx != &obj->index) {
		/* a substitution is already registered for this key */
		kfree(obj);

		obj = container_of(idx, struct substitution_file, index);
		if (obj->file == file)
			r = -EALREADY;
		else
			r = -ENOKEY;
	} else
		r = 0;
error:
	return r;
}

static int insert_one_substitution_file(struct rb_root *files,
					enum shared_obj_type type,
					unsigned long key,
					kerrighed_node_t node,
					int fd)
{
	int r, fdesc_size;
	size_t file_link_size;
	struct file *file;
	void *fdesc, *cr_file_link;

	if (type != LOCAL_FILE
	    && type != DVFS_FILE) {
		r = -EINVAL;
		goto error;
	}

	file = fget(fd);
	if (!file) {
		r = -EINVAL;
		goto error;
	}

	if (!file->f_objid) {
		r = create_kddm_file_object(file);
		if (r)
			goto err_put_file;
	}

	r = setup_faf_file_if_needed(file);
	if (r)
		goto err_put_file;

	if (file->f_flags & (O_FAF_SRV|O_FAF_CLT))
		r = get_faf_file_krg_desc(file, &fdesc, &fdesc_size);
	else
		r = get_regular_file_krg_desc(file, &fdesc, &fdesc_size);

	if (r)
		goto err_put_file;

	r = prepare_restart_data_shared_file(file, fdesc, fdesc_size,
					     &cr_file_link, &file_link_size,
					     true);
	if (r)
		goto err_free_desc;

	r = __insert_one_substitution_file(files, type, key, node,
					   file_link_size, cr_file_link, file);
	if (r) {
		if (r == -EALREADY)
			/* the same file substitution has already
			 * been registered */
			r = 0;

		goto err_free_file_link;
	}

error:
	return r;

err_free_file_link:
	kfree(cr_file_link);
err_free_desc:
	kfree(fdesc);
err_put_file:
	fput(file);
	goto error;
}

static int parse_file_identifier(char *str, enum shared_obj_type *type,
				 unsigned long *key, kerrighed_node_t *node)
{
	int r, nodelen, keylen, len;
	char saved_c;

	nodelen = sizeof(*node)*2;
	keylen = sizeof(*key)*2;
	len = strlen(str);

	if (len != nodelen + keylen)
		goto err_invalid;

	/* read the key */
	r = sscanf(str + nodelen, "%lX", key);
	if (r != 1)
		goto err_invalid;

	/* read the node */
	saved_c = str[nodelen];
	str[nodelen] = '\0';

	r = sscanf(str, "%hX", node);

	str[nodelen]= saved_c;

	if (r != 1)
		goto err_invalid;

	r = 0;

	if (*node == KERRIGHED_NODE_ID_NONE)
		*type = DVFS_FILE;
	else
		*type = LOCAL_FILE;

out:
	return r;

err_invalid:
	r = -EINVAL;
	goto out;
}

static int insert_substitution_files(struct rb_root *files,
				     struct restart_request *req)
{
	int i, r = 0;
	enum shared_obj_type type;
	unsigned long key;
	kerrighed_node_t node;

	for (i = 0; i < req->substitution.nr; i++) {

		r = parse_file_identifier(req->substitution.files[i].file_id,
					  &type, &key, &node);
		if (r)
			goto error;

		r = insert_one_substitution_file(
			files, type, key, node,
			req->substitution.files[i].fd);
		if (r)
			goto error;
	}

error:
	return r;
}

/*--------------------------------------------------------------------------*/

int local_restart_shared_complete(struct app_struct *app,
				  struct task_struct *fake)
{
	struct rb_node *node;

	reset_fake_task_struct(fake);

	while ((node = rb_first(&app->shared_objects.root))) {
		struct shared_index *idx =
			container_of(node, struct shared_index, node);

		struct shared_object *this =
			container_of(idx, struct shared_object, index);

		BUG_ON(this->restart.locality == SHARED_ANY);

		if (this->restart.locality == LOCAL_ONLY
		    || this->restart.locality == SHARED_MASTER)
			this->ops->import_complete(fake, this->restart.data);

		rb_erase(node, &app->shared_objects.root);
		kfree(this);
	}

	return 0;
}

static int local_restart_shared_objects(struct rpc_desc *desc,
					struct app_struct *app,
					struct task_struct *fake,
					int chkpt_sn,
					enum shared_obj_type from,
					enum shared_obj_type to,
					loff_t ghost_offsets[])
{
	int r = -EINVAL;
	int idx = 0;
	kerrighed_node_t node;
	struct epm_action action;
	ghost_t *ghost;

	action.type = EPM_RESTART;
	action.restart.appid = app->app_id;
	action.restart.shared = CR_LOAD_NOW;
	action.restart.app = app;

	/* 1) restore objects for which we are master */
	for_each_krgnode_mask(node, app->restart.replacing_nodes) {

		ghost = create_file_ghost(GHOST_READ, app->app_id, chkpt_sn,
					  "shared_obj_%d.bin", node);

		if (IS_ERR(ghost)) {
			r = PTR_ERR(ghost);
			epm_error(&action, r, NULL,
				  "Fail to open file "
				  "/var/chkpt/%ld/v%d/shared_obj_%u.bin",
				  app->app_id, chkpt_sn, kerrighed_node_id);
			goto err_import;
		}

		set_file_ghost_pos(ghost, ghost_offsets[idx]);

		r = import_shared_objects(&action, ghost, fake);
		if (r)
			goto err_close_ghost;

		ghost_offsets[idx] = get_file_ghost_pos(ghost);

		ghost_close(ghost);

		idx++;
	}

err_import:
	r = send_result(desc, r);
	if (r)
		goto err;

	/* 2) send list of restored objects that are shared with other nodes */
	r = send_restored_objects(desc, app, from, to);

	r = send_result(desc, r);
	if (r)
		goto err;

	/* 3) receive objects information from other nodes */
	r = rcv_full_restored_objects(desc, app);
	if (r)
		goto err;

err:
	return r;

err_close_ghost:
	ghost_close(ghost);
	goto err;
}

int local_restart_shared(struct rpc_desc *desc,
			 struct app_struct *app,
			 struct task_struct *fake,
			 int chkpt_sn)
{

	loff_t *ghost_offsets;
	ghost_fs_t oldfs;
	int r, nb_nodes;

	__set_ghost_fs(&oldfs);

	nb_nodes = krgnodes_weight(app->restart.replacing_nodes);

	ghost_offsets = kzalloc(nb_nodes * sizeof(int), GFP_KERNEL);
	if (!ghost_offsets) {
		r = -ENOMEM;
		goto err_ghost_fs;
	}

	/* 1) get files replaced by coordinator */
	r = rcv_substitution_files(desc, app);
	if (r)
		goto err_ghost_offset;

	/* 2) restore pipes and files */
	r = local_restart_shared_objects(desc, app, fake, chkpt_sn,
					 PIPE_INODE, DVFS_FILE,
					 ghost_offsets);
	if (r)
		goto err_ghost_offset;

	/* 3) restore other objects */
	r = local_restart_shared_objects(desc, app, fake, chkpt_sn,
					 FILES_STRUCT, SIGNAL_STRUCT,
					 ghost_offsets);
	if (r)
		goto err_ghost_offset;

err_ghost_offset:
	kfree(ghost_offsets);

err_ghost_fs:
	unset_ghost_fs(&oldfs);
	return r;
}

static int global_restart_shared_objects(struct rpc_desc *desc,
					 struct app_kddm_object *obj)
{
	int r = 0;
	int err_rpc = 0;
	kerrighed_node_t node;
	struct rb_root dist_shared_indexes = RB_ROOT;

	/* 1) waiting nodes to have restored objects they are master for */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto error;

	/* 2) request the list of restored distributed objects */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	for_each_krgnode_mask(node, obj->nodes) {
		r = rcv_restored_dist_objects_list_from(desc,
							&dist_shared_indexes,
							node);
		if (r)
			goto error;
	}
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto error;

	/* 3) Send the list to every node
	 * this is not optimized but otherwise, we need to open
	 * a new RPC desc to each node */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	r = send_full_restored_dist_objects_list(desc, &dist_shared_indexes);

error:
	clear_restored_dist_shared_indexes(&dist_shared_indexes);
	return r;
err_rpc:
	r = err_rpc;
	goto error;
}

int global_restart_shared(struct rpc_desc *desc,
			  struct app_kddm_object *obj,
			  struct restart_request *req)
{
	int r = 0;
	struct rb_root substitute_files = RB_ROOT;

	r = insert_substitution_files(&substitute_files, req);
	if (r)
		goto error;

	/* send list of files replaced at restart time by coordinator */
	r = send_substitution_files(desc, &substitute_files);
	if (r)
		goto error;

	/* manage shared pipes and files */
	r = global_restart_shared_objects(desc, obj);
	if (r)
		goto error;

	/* manage shared objects */
	r = global_restart_shared_objects(desc, obj);
	if (r)
		goto error;

error:
	clear_substitution_files(&substitute_files);
	if (r)
		app_error(__krg_action_to_str(EPM_RESTART), r, obj->app_id,
			  "Fail to restore shared objects");

	return r;
}

