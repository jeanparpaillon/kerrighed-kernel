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

#include <linux/rbtree.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/unique_id.h>

#include <kerrighed/task.h>
#include <net/krgrpc/rpc.h>
#include <kddm/kddm.h>
#include <kerrighed/application.h>
#include <kerrighed/app_shared.h>
#include "app_utils.h"

/*--------------------------------------------------------------------------*/

extern struct shared_object_operations cr_shared_regular_file_ops;
extern struct shared_object_operations cr_shared_dvfs_regular_file_ops;
extern struct shared_object_operations cr_shared_faf_file_ops;
extern struct shared_object_operations cr_shared_files_struct_ops;
extern struct shared_object_operations cr_shared_fs_struct_ops;
extern struct shared_object_operations cr_shared_mm_struct_ops;
extern struct shared_object_operations cr_shared_semundo_ops;
/* TODO PORT */
/*extern*/ struct shared_object_operations cr_shared_sighand_struct_ops;
/*extern*/ struct shared_object_operations cr_shared_signal_struct_ops;

static struct shared_object_operations * get_shared_ops(
	enum shared_obj_type type)
{
	struct shared_object_operations * s_ops = NULL;

	switch (type) {
	case REGULAR_FILE:
		s_ops = &cr_shared_regular_file_ops;
		break;
	case REGULAR_DVFS_FILE:
		s_ops = &cr_shared_dvfs_regular_file_ops;
		break;
	case FAF_FILE:
		s_ops = &cr_shared_faf_file_ops;
		break;
	case FILES_STRUCT:
		s_ops = &cr_shared_files_struct_ops;
		break;
	case FS_STRUCT:
		s_ops = &cr_shared_fs_struct_ops;
		break;
	case MM_STRUCT:
		s_ops = &cr_shared_mm_struct_ops;
		break;
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


static int insert_shared_index(struct rb_root *root,
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
				return -ENOKEY;
		}
	}

	/* Add new node and rebalance tree. */
	rb_link_node(&idx->node, parent, new);
	rb_insert_color(&idx->node, root);

	return 0;
}

/*--------------------------------------------------------------------------*/

enum locality {
	LOCAL_ONLY,
	SHARED_MASTER,
	SHARED_SLAVE
};

struct shared_object {
	struct shared_index index;
	struct shared_object_operations *ops;

	union {
		struct {
			struct task_struct *exporting_task;
			union export_args args;
			int is_local;
		} checkpoint;
		struct {
			struct task_identity t_identity;
			void *data;
			enum locality locality;
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

void * get_imported_shared_object(struct rb_root *root,
				  enum shared_obj_type type,
				  unsigned long key)
{
	void *data = NULL;
	struct shared_object *s;

	s = search_shared_object(root, type, key);
	if (s)
		data = s->restart.data;

	return data;
}

/* to use only at checkpoint time! */
int add_to_shared_objects_list(struct rb_root *root,
			       enum shared_obj_type type,
			       unsigned long key,
			       int is_local,
			       struct task_struct *exporting_task,
			       union export_args *args)
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

	r = insert_shared_index(root, &s->index);
	if (r) {
		/* shared object is already in the list */
		kfree(s);
#ifdef CONFIG_KRG_DEBUG
		s = search_shared_object(root, type, key);
		BUG_ON(!s);
#endif
	} else {
		/* the object was not in the list, finishing initialization */
		s->ops = s_ops;
		s->checkpoint.exporting_task = exporting_task;
		if (args)
			s->checkpoint.args = *args;
		s->checkpoint.is_local = is_local;
	}
	return r;
}

static void clear_one_shared_object(struct rb_node *node,
				    struct app_struct *app)
{
	struct shared_index *idx =
		container_of(node, struct shared_index, node);

	struct shared_object *this =
		container_of(idx, struct shared_object, index);

	rb_erase(node, &app->shared_objects);
	kfree(this);
}

void clear_shared_objects(struct app_struct *app)
{
	struct rb_node *node;

	while ((node = rb_first(&app->shared_objects)))
		clear_one_shared_object(node, app);
}

static inline void reset_fake_task_struct(struct task_struct *fake,
					  struct app_struct *app)
{
	memset(fake, 0, sizeof(struct task_struct));
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

	rb_erase(node, &app->shared_objects);

	fake->pid = this->restart.t_identity.pid;
	fake->tgid = this->restart.t_identity.tgid;

	this->ops->delete(fake, this->restart.data);

	kfree(this);
}

void destroy_shared_objects(struct app_struct *app,
			    struct task_struct *fake)
{
	struct rb_node *node;

	reset_fake_task_struct(fake, app);

	while ((node = rb_first(&app->shared_objects)))
		destroy_one_shared_object(node, app, fake);
}

/*--------------------------------------------------------------------------*/


static int export_one_shared_object(ghost_t *ghost,
				    struct epm_action *action,
				    struct shared_object *this)
{
	int r;
	struct task_identity t;
	t.pid = this->checkpoint.exporting_task->pid;
	t.tgid = this->checkpoint.exporting_task->tgid;

	r = ghost_write(ghost, &this->index.type,
			sizeof(enum shared_obj_type));
	if (r)
		goto error;
	r = ghost_write(ghost, &this->index.key, sizeof(long));
	if (r)
		goto error;
	r = ghost_write(ghost, &t, sizeof(struct task_identity));
	if (r)
		goto error;
	r = ghost_write(ghost, &this->checkpoint.is_local, sizeof(int));
	if (r)
		goto error;

	r = this->ops->export_now(action, ghost,
				  this->checkpoint.exporting_task,
				  &this->checkpoint.args);

error:
	return r;
}

static int __export_shared_objects(ghost_t *ghost,
				   struct app_struct *app,
				   int file)
{
	int r = 0;
	enum shared_obj_type end = NO_OBJ;
	struct epm_action action;
	struct rb_node *node, *next_node;

	action.type = EPM_CHECKPOINT;
	action.checkpoint.shared = CR_SAVE_NOW;

	node = rb_first(&app->shared_objects);
	while (node) {
		struct shared_index *idx;
		struct shared_object *this;

		next_node = rb_next(node);

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct shared_object, index);

		if (file && idx->type == FILES_STRUCT)
			goto exit_write_end;

		r = export_one_shared_object(ghost, &action, this);
		clear_one_shared_object(node, app);

		if (r)
			goto error;

		node = next_node;
	}

exit_write_end:
	r = ghost_write(ghost, &end,
			sizeof(enum shared_obj_type));
error:
	return r;
}

static int export_shared_files(ghost_t *ghost, struct app_struct *app)
{
	return __export_shared_objects(ghost, app, 1);
}

static int export_shared_objects_but_files(ghost_t *ghost,
					   struct app_struct *app)
{
	return __export_shared_objects(ghost, app, 0);
}

static int chkpt_shared_objects(struct app_struct *app,
				int chkpt_sn,
				struct credentials *user_creds)
{
	int r;

	ghost_fs_t oldfs;
	ghost_t *ghost;

	r = set_ghost_fs(&oldfs, user_creds->uid, user_creds->gid);
	if (r)
		goto exit;

	ghost = create_file_ghost(GHOST_WRITE, app->app_id, chkpt_sn,
				  kerrighed_node_id, "shared_obj");

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto exit_unset_fs;
	}

	r = export_shared_files(ghost, app);
	if (r)
		goto exit_close_ghost;

	r = export_shared_objects_but_files(ghost, app);

exit_close_ghost:
	/* End of the really interesting part */
	ghost_close(ghost);

exit_unset_fs:
	unset_ghost_fs(&oldfs);

exit:
	return r;
}

/*--------------------------------------------------------------------------*/

static int send_dist_objects_list(struct rpc_desc *desc,
				  struct app_struct *app)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(&app->shared_objects);
	     node ; node = rb_next(node) ) {
		struct shared_index *idx;
		struct shared_object *this;
		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct shared_object, index);

		if (!this->checkpoint.is_local) {
			r = rpc_pack_type(desc, idx->type);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, idx->key);
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
	kerrighed_node_t node;
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
		unsigned long key;

		r = rpc_unpack_type_from(desc, node, key);
		if (r)
			goto error;

		s = kmalloc(sizeof(struct dist_shared_index), GFP_KERNEL);
		if (!s) {
			r = -ENOMEM;
			goto error;
		}

		s->index.type = type;
		s->index.key = key;
		s->node = node;

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

		r = rpc_pack_type(desc, idx->type);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, idx->key);
		if (r)
			goto err_pack;

		r = rpc_pack_type(desc, this->node);
		if (r)
			goto err_pack;
	}
	r = rpc_pack_type(desc, end);

err_pack:
	return r;
}


static int rcv_full_dist_objects_list(struct rpc_desc *desc,
				      struct app_struct *app)

{
	int r;
	struct dist_shared_index s;

	r = rpc_unpack_type(desc, s.index.type);
	if (r)
		goto error;

	while (s.index.type != NO_OBJ) {

		r = rpc_unpack_type(desc, s.index.key);
		if (r)
			goto error;

		r = rpc_unpack_type(desc, s.node);
		if (r)
			goto error;

		if (s.node != kerrighed_node_id) {
			struct rb_node *node;
			node = search_node(&app->shared_objects,
					   s.index.type, s.index.key);

			if (node)
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
		       int chkpt_sn,
		       struct credentials *user_creds)
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
	r = chkpt_shared_objects(app, chkpt_sn, user_creds);
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


static int import_one_shared_object(ghost_t *ghost, struct epm_action *action,
				    struct task_struct *fake,
				    enum shared_obj_type type)
{
	int r;
	struct shared_object_operations *s_ops;
	struct shared_object *s;
	int is_local;

	s_ops = get_shared_ops(type);

	s = kmalloc(sizeof(struct shared_object) + s_ops->restart_data_size,
		    GFP_KERNEL);

	if (!s) {
		r = -ENOMEM;
		goto err;
	}

	BUG_ON(type == NO_OBJ);

	s->index.type = type;
	s->ops = s_ops;

	if (s->ops->restart_data_size)
		s->restart.data = &s[1];
	else
		s->restart.data = NULL;

	r = ghost_read(ghost, &s->index.key, sizeof(long));
	if (r)
		goto err_free;
	r = ghost_read(ghost, &s->restart.t_identity, sizeof(struct task_identity));
	if (r)
		goto err_free;

	fake->pid = s->restart.t_identity.pid;
	fake->tgid = s->restart.t_identity.tgid;

	r = ghost_read(ghost, &is_local, sizeof(int));
	if (r)
		goto err_free;

	if (is_local)
		s->restart.locality = LOCAL_ONLY;
	else
		s->restart.locality = SHARED_MASTER;

	r = s->ops->import_now(action, ghost, fake, &s->restart.data);
	if (r)
		goto err_free;

	BUG_ON(!s->restart.data);

	r = insert_shared_index(&fake->application->shared_objects, &s->index);

err_free:
	if (r)
		kfree(s);
err:
	return r;
}

static int __import_shared_objects(ghost_t *ghost, struct app_struct *app,
				   struct task_struct *fake)
{
	int r;
	struct epm_action action;
	enum shared_obj_type type = NO_OBJ;

	action.type = EPM_CHECKPOINT;
	action.restart.shared = CR_LOAD_NOW;
	action.restart.app = app;

	r = ghost_read(ghost, &type, sizeof(enum shared_obj_type));
	if (r)
		goto error;

	reset_fake_task_struct(fake, app);

	while (type != NO_OBJ) {

		r = import_one_shared_object(ghost, &action, fake, type);
		if (r)
			goto error;

		r = ghost_read(ghost, &type, sizeof(enum shared_obj_type));
		if (r)
			goto error;
	}

error:
	return r;
}

static int import_shared_files(ghost_t *ghost, struct app_struct *app,
			       struct task_struct *fake)
{
	return __import_shared_objects(ghost, app, fake);
}

static int import_shared_objects_but_files(ghost_t *ghost,
					   struct app_struct *app,
					   struct task_struct *fake)
{
	return __import_shared_objects(ghost, app, fake);
}


static int __send_restored_objects(struct rpc_desc *desc,
				   struct app_struct *app,
				   int file_only)
{
	enum shared_obj_type end = NO_OBJ;
	struct rb_node *node;
	int r;

	for (node = rb_first(&app->shared_objects);
	     node ; node = rb_next(node) ) {

		struct shared_object *this;
		struct shared_index *idx;

		idx = container_of(node, struct shared_index, node);
		this = container_of(idx, struct shared_object, index);

		if (this->restart.locality == SHARED_MASTER &&
		    (
			    file_only ||
			    (idx->type != REGULAR_FILE &&
			     idx->type != REGULAR_DVFS_FILE &&
			     idx->type != FAF_FILE)
			    )) {
			r = rpc_pack_type(desc, idx->type);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, idx->key);
			if (r)
				goto err_pack;

			r = rpc_pack_type(desc, this->ops->restart_data_size);
			if (r)
				goto err_pack;

			if (this->ops->restart_data_size)
				r = rpc_pack(desc, 0, this->restart.data,
					     this->ops->restart_data_size);
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

static int send_restored_files(struct rpc_desc *desc,
			       struct app_struct *app)
{
	return __send_restored_objects(desc, app, 1);
}

static int send_restored_objects_but_files(struct rpc_desc *desc,
					   struct app_struct *app)
{
	return __send_restored_objects(desc, app, 0);
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
		r = insert_shared_index(&app->shared_objects, &obj->index);
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

int local_restart_shared_complete(struct app_struct *app,
				  struct task_struct *fake)
{
	struct rb_node *node;

	reset_fake_task_struct(fake, app);

	while ((node = rb_first(&app->shared_objects))) {
		struct shared_index *idx =
			container_of(node, struct shared_index, node);

		struct shared_object *this =
			container_of(idx, struct shared_object, index);

		fake->pid = this->restart.t_identity.pid;
		fake->tgid = this->restart.t_identity.tgid;

		if (this->restart.locality == LOCAL_ONLY
		    || this->restart.locality == SHARED_MASTER) {
			fake->pid = this->restart.t_identity.pid;
			fake->tgid = this->restart.t_identity.tgid;
			this->ops->import_complete(fake, this->restart.data);
		}

		rb_erase(node, &app->shared_objects);
		kfree(this);
	}

	return 0;
}

int local_restart_shared(struct rpc_desc *desc,
			 struct app_struct *app,
			 struct task_struct *fake,
			 int chkpt_sn,
			 struct credentials *user_creds)
{
	ghost_fs_t oldfs;
	ghost_t *ghost;

	int r;

	r = set_ghost_fs(&oldfs, user_creds->uid, user_creds->gid);
	if (r)
		goto error;

	ghost = create_file_ghost(GHOST_READ, app->app_id, chkpt_sn,
				  kerrighed_node_id, "shared_obj");

	if (IS_ERR(ghost)) {
		r = PTR_ERR(ghost);
		goto err_create_ghost;
	}

	/* 1) restore shared files */
	r = import_shared_files(ghost, app, fake);

	r = send_result(desc, r);
	if (r)
		goto err_ghost;

	/* 2) send list of restored "distributed" shared files */
	r = send_restored_files(desc, app);

	r = send_result(desc, r);
	if (r)
		goto err_ghost;

	/* 3) receive updated information about shared files */
	r = rcv_full_restored_objects(desc, app);
	if (r)
		goto err_ghost;

	/* 4) restore shared objects */
	r = import_shared_objects_but_files(ghost, app, fake);

	ghost_close(ghost);
	unset_ghost_fs(&oldfs);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* 5) send list of restored "distributed" shared objects */
	r = send_restored_objects_but_files(desc, app);

	r = send_result(desc, r);
	if (r)
		goto error;

	/* 6) receive updated information about shared objects */
	r = rcv_full_restored_objects(desc, app);

	r = send_result(desc, r);
	if (r)
		goto error;
error:
	return r;

err_ghost:
	ghost_close(ghost);

err_create_ghost:
	unset_ghost_fs(&oldfs);

	goto error;
}

int global_restart_shared(struct rpc_desc *desc,
			  struct app_kddm_object *obj)
{
	int r = 0;
	int err_rpc = 0;
	kerrighed_node_t node;
	struct rb_root dist_shared_indexes = RB_ROOT;

	/* 1) request the nodes to restore their files */

        /* waiting results from the nodes hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto error;

	/* 2) request the list of restored distributed files */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	for_each_krgnode_mask(node, obj->nodes) {
		r = rcv_restored_dist_objects_list_from(desc,
							&dist_shared_indexes,
							node);
		if (r)
			goto err_clear_shared;
	}
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto err_clear_shared;

	/* 3) Send the list to every node
	 * this is not optimized but otherwise, we need to open
	 * a new RPC desc to each node */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc_clear_shared;

	r = send_full_restored_dist_objects_list(desc, &dist_shared_indexes);

	clear_restored_dist_shared_indexes(&dist_shared_indexes);

	/* 4) request the nodes to restore their objects */

        /* waiting results from the nodes hosting the application */
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto error;

	/* 5) request the list of restored distributed objects */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc;

	for_each_krgnode_mask(node, obj->nodes) {
		r = rcv_restored_dist_objects_list_from(desc,
							&dist_shared_indexes,
							node);
		if (r)
			goto err_clear_shared;
	}
	r = app_wait_returns_from_nodes(desc, obj->nodes);
	if (r)
		goto err_clear_shared;

	/* 6) Send the list to every node
	 * this is not optimized but otherwise, we need to open
	 * a new RPC desc to each node */
	err_rpc = rpc_pack_type(desc, r);
	if (err_rpc)
		goto err_rpc_clear_shared;

	r = send_full_restored_dist_objects_list(desc, &dist_shared_indexes);
	if (r)
		goto err_clear_shared;

	r = app_wait_returns_from_nodes(desc, obj->nodes);

err_clear_shared:
	clear_restored_dist_shared_indexes(&dist_shared_indexes);

error:
	return r;

err_rpc_clear_shared:
	r = err_rpc;
	goto err_clear_shared;

err_rpc:
	r = err_rpc;
	goto error;
}

