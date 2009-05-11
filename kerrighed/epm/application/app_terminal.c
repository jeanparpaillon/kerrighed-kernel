/*
 * Application management of (pseudo-)terminal
 *
 *  Copyright (C) 2009 Matthieu Fertré - Kerlabs
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <net/krgrpc/rpc.h>
#include <linux/file.h>
#include <kerrighed/file.h>
#include <kerrighed/fs_mobility.h>
#include <kerrighed/regular_file_mgr.h>
#include <kerrighed/faf.h>
#include <kerrighed/faf_file_mgr.h>
#include <kerrighed/app_terminal.h>
#include <kerrighed/app_shared.h>

extern const struct file_operations tty_fops;
extern const struct file_operations hung_up_tty_fops;

int is_tty(struct file *file)
{
	int r = 0;

	if (file->f_flags & O_FAF_CLT) {
		if (file->f_flags & O_FAF_TTY)
			r = 1;
	} else if (file->f_op == &tty_fops
		   || file->f_op == &hung_up_tty_fops)
		r = 1;

	return r;
}

struct file *get_valid_terminal(void)
{
	struct file *stdin, *stdout, *stderr, *term;

	stdin = fget(0);
	stdout = fget(1);
	stderr = fget(2);

	if (stdin == stdout
	    && stdin == stderr
	    && is_tty(stdin))
		term = stdin;
	else
		term = NULL;

	if (!term)
		fput(stdin);

	fput(stdout);
	fput(stderr);
	return term;
}

void app_set_checkpoint_terminal(struct app_struct *app,
				 struct file *stdfile)
{
	if (!app->checkpoint.terminal) {
		app->checkpoint.terminal = stdfile;
	} else if (app->checkpoint.terminal != stdfile)
		app->checkpoint.terminal = ERR_PTR(-EPERM);
}

static void app_unset_checkpoint_terminal(struct app_struct *app)
{
	app->checkpoint.terminal = NULL;
}

void app_set_restart_terminal(struct app_struct *app, struct file *stdfile)
{
	BUG_ON(app->restart.terminal);
	app->restart.terminal = stdfile;
}

struct file *app_get_restart_terminal(struct app_struct *app)
{
	struct file* std = app->restart.terminal;

	if (std)
		get_file(std);

	return std;
}

int send_terminal_desc(struct rpc_desc *desc, struct file *tty)
{
	void *fdesc;
	int fdesc_size;
	int r;

	if (!tty->f_objid) {
		r = create_kddm_file_object(tty);
		if (r)
			goto error;
        }

	r = setup_faf_file_if_needed(tty);
	if (r == -EALREADY)
		r = 0;

	if (!(tty->f_flags & (O_FAF_SRV | O_FAF_CLT)))
		r = -EINVAL;

	if (r)
		goto error;

	r = get_faf_file_krg_desc(tty, &fdesc, &fdesc_size);
	if (r)
		goto error;

	r = rpc_pack_type(desc, tty->f_objid);
	if (r)
		goto err_free_desc;

	r = rpc_pack_type(desc, fdesc_size);
	if (r)
		goto err_free_desc;

	r = rpc_pack(desc, 0, fdesc, fdesc_size);

err_free_desc:
	kfree(fdesc);

error:
	return r;
}

int rcv_terminal_desc(struct rpc_desc *desc, struct app_struct *app)
{
	int r;
	void *fdesc;
	int fdesc_size;
	long fobjid;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file;
	int first_import = 0;

	r = rpc_unpack_type(desc, fobjid);
	if (r)
		goto error;

	r = rpc_unpack_type(desc, fdesc_size);
	if (r)
		goto error;

	fdesc = kmalloc(GFP_KERNEL, fdesc_size);
	if (!fdesc) {
		r = -ENOMEM;
		goto error;
	}

	r = rpc_unpack(desc, 0, fdesc, fdesc_size);
	if (r)
		goto err_free_desc;

	/* Check if the file struct is already present */
	file = begin_import_dvfs_file(fobjid, &dvfs_file);

	if (!file) {
		file = create_faf_file_from_krg_desc(current, fdesc);
		first_import = 1;
	}

	r = end_import_dvfs_file(fobjid, dvfs_file, file, first_import);
	if (r)
		goto err_free_desc;

	app_set_restart_terminal(app, file);

err_free_desc:
	kfree(fdesc);

error:
	return r;
}

void app_put_terminal(struct app_struct *app)
{
	if (app->restart.terminal) {
		fput(app->restart.terminal);
		app->restart.terminal = NULL;
	}
}

int send_terminal_id(struct rpc_desc *desc, struct app_struct *app)
{
	int r;
	int one_terminal = 1;
	enum shared_obj_type type;
	long key;

	if (!app->checkpoint.terminal || IS_ERR(app->checkpoint.terminal))
		one_terminal = 0;

	r = rpc_pack_type(desc, one_terminal);
	if (r)
		goto exit;

	if (!one_terminal)
		goto exit;

	cr_get_file_type_and_key(app->checkpoint.terminal, &type, &key);

	r = rpc_pack_type(desc, type);
	if (r)
		goto exit;

	r = rpc_pack_type(desc, key);

exit:
	app_unset_checkpoint_terminal(app);
	return r;
}

int rcv_terminal_id(struct rpc_desc *desc, krgnodemask_t nodes,
		    int *one_terminal)
{
	int r = 0;
	int one_local_terminal;
	enum shared_obj_type type = NO_OBJ, type2;
	long key = 0, key2;
	kerrighed_node_t node;

	*one_terminal = 1;

	for_each_krgnode_mask(node, nodes) {
		r = rpc_unpack_type_from(desc, node, one_local_terminal);
		if (r)
			goto exit;

		if (!one_local_terminal) {
			*one_terminal = 0; /* false */
			continue;
		}

		r = rpc_unpack_type_from(desc, node, type2);
		if (r)
			goto exit;

		r = rpc_unpack_type_from(desc, node, key2);
		if (r)
			goto exit;

		if (type == NO_OBJ) {
			type = type2;
			key = key2;
		} else if (type != type2 || key != key2)
			*one_terminal = 0; /* false */
	}

exit:
	return r;
}
