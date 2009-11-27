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
#include <kerrighed/ghost_helpers.h>
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

	if (!file)
		return 0;

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
	term = NULL;

	if (is_tty(stdin))
		term = stdin;

	if (is_tty(stdout)) {
		if (!term)
			term = stdout;
		else if (term != stdout)
			goto err;
	}

	if (is_tty(stderr)) {
		if (!term)
			term = stderr;
		else if (term != stderr)
			goto err;
	}

exit:
	if (term)
		get_file(term);

	if (stdin)
		fput(stdin);
	if (stdout)
		fput(stdout);
	if (stderr)
		fput(stderr);
	return term;

err:
	term = NULL;
	goto exit;
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
	int r;

	r = send_faf_file_desc(desc, tty);

	return r;
}

int rcv_terminal_desc(struct rpc_desc *desc, struct app_struct *app)
{
	int r = 0;
	struct file *file;

	file = rcv_faf_file_desc(desc);
	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto error;
	}

	app_set_restart_terminal(app, file);
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

	cr_get_file_type_and_key(app->checkpoint.terminal, &type, &key, 0);

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
