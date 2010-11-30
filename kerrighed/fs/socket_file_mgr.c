#include <linux/file.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <kerrighed/action.h>
#include <kerrighed/file.h>
#include <kerrighed/socket_file_mgr.h>
#include <kerrighed/checkpoint_sock.h>
#include "mobility.h"


struct krgip_sockinfo {
	int flags;
	unsigned short family;
	unsigned short type;
	unsigned char protocol;
};


/*****************************************************************************/
/*                                                                           */
/*                           SOCKET FILES IMPORT/EXPORT                      */
/*                                                                           */
/*****************************************************************************/


static int krgip_export_sockfile(struct epm_action *action,
				 ghost_t *ghost, struct file *file)
{
	int ret;
	struct socket *sock = file->private_data;
	struct krgip_sockinfo sockinfo = {
		.flags = file->f_flags,
		.family = sock->sk->sk_family,
		.type = sock->type,
		.protocol = sock->sk->sk_protocol,
	};

/*	int flags = file->f_flags;
	ret = ghost_write(ghost, &flags, sizeof(flags));
	if (ret)
		goto out;
*/

	ret = ghost_write(ghost, &sockinfo, sizeof(sockinfo));
	if (ret)
		goto out;

	ret = krgip_export_sock(action, ghost, sock);

out:
	sock_release(sock);
	/*fputs(file);*/

	return ret;
}

static int krgip_import_sockfile(struct epm_action *action,
				 ghost_t *ghost, struct file **file)
{
	int ret;
	struct file *sockfile;
/*	struct socket *sock;*/
	struct krgip_sockinfo sockinfo;

/*	int flags;
	ret = ghost_read(ghost, &flags, sizeof(flags));
	if (ret)
		goto out;
*/

	ret = ghost_read(ghost, &sockinfo, sizeof(sockinfo));
	if (ret)
		goto out;

	sockfile = get_empty_filp();
	if (!sockfile) {
		ret = -ENOMEM;
		goto out;
	}
/*
	ret = krgip_sock_alloc(sockfile, flags, &sock);
	if (ret)
		goto out_err;
*/

	ret = krgip_sock_create_and_attach(sockinfo.family, sockinfo.type, sockinfo.protocol,
					   sockfile, sockinfo.flags);
	if (ret)
		goto out_err;

	ret = krgip_import_sock(action, ghost, sockfile->private_data);
	if (ret)
		goto out_err;

	*file = sockfile;

out:
	return ret;
out_err:
	sock_release(sockfile->private_data);
	/*fput(sockfile);*/
	goto out;
}


int socket_file_export(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *task, int index, struct file *file)
{
	int ret;

	BUG_ON(action->type == EPM_CHECKPOINT);

	/* Puts checks and branches here */
	pr_debug("Exporting socket file\n");

	ret = krgip_export_sockfile(action, ghost, file);
	if (ret)
		pr_debug("socket_file_export() returned error %d\n", ret);
	return ret;
}

int socket_file_import(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *task, struct file **returned_file)
{
	int ret;

	BUG_ON(action->type == EPM_CHECKPOINT);

	/* Puts checks and branches here */
	pr_debug("Importing socket file\n");

	ret = krgip_import_sockfile(action, ghost, returned_file);
	if (ret)
		pr_debug("socket_file_import() returned error %d\n", ret);
	return ret;
}


struct dvfs_mobility_operations dvfs_mobility_sock_ops = {
	.file_export = socket_file_export,
	.file_import = socket_file_import,
};

