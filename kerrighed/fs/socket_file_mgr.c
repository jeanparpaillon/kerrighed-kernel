#include <linux/file.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <kerrighed/action.h>
#include <kerrighed/file.h>
#include <kerrighed/file_stat.h>
#include <kerrighed/krg_clusterip.h>
#include <kerrighed/socket_file_mgr.h>
#include <kerrighed/checkpoint_sock.h>
#include "mobility.h"

struct krgip_sockinfo {
	int flags;
	unsigned short family;
	unsigned short type;
	unsigned char protocol;
};

int krgip_migration_debug(int revert)
{
	static int debug = 0;

	return 1;

	if (revert)
		debug = ~debug;

	return debug;
}

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

	ret = ghost_write(ghost, &sockinfo, sizeof(sockinfo));
	if (ret)
		goto out;

	ret = krgip_export_sock(action, ghost, sock);

out:
	return ret;
}

static int krgip_import_sockfile(struct epm_action *action,
				 ghost_t *ghost, struct file **file)
{
	int ret;
	struct file *sockfile;
	struct krgip_sockinfo sockinfo;

	ret = ghost_read(ghost, &sockinfo, sizeof(sockinfo));
	if (ret)
		goto out;

	sockfile = get_empty_filp();
	if (!sockfile) {
		ret = -ENOMEM;
		goto out;
	}

	ret = krgip_sock_create_and_attach(sockinfo.family, sockinfo.type, sockinfo.protocol,
					   sockfile, sockinfo.flags);
	if (ret)
		goto out_err;
	ret = krgip_import_sock(action, ghost, sockfile->private_data);
	if (ret)
		goto out_err;

	*file = sockfile;

	pr_debug("sk_family : %hu\n", ((struct socket*) sockfile->private_data)->sk->sk_family);
out:
	return ret;
out_err:
	/*sock_release(sockfile->private_data);*/
	fput(sockfile);
	goto out;
}

int socket_file_faf_policy(struct epm_action *action, struct task_struct *task,
			   int index, struct file *file)
{
	struct socket *sock;

	BUG_ON(action->type == EPM_CHECKPOINT);
	BUG_ON(!is_socket(file));

	sock = file->private_data;

	if (sock->sk->sk_family != PF_INET) {
		pr_debug("not a INET socket (family is %hu), use faf\n", sock->sk->sk_family);
		return 0;
	}

	if (!inet_sk(sock->sk)->saddr && ! inet_sk(sock->sk)->is_krgip) {
		pr_debug("%u.%u.%u.%u is not a kerrighed ip, use faf\n",
			 SPLIT_IP4_ADDR(inet_sk(sock->sk)->saddr));
		return 0;
	}

	if (sock->sk->sk_protocol != IPPROTO_UDP && sock->sk->sk_protocol != IPPROTO_TCP) {
		pr_debug("not a udp nor tcp socket (protocol is %u), use faf\n",
			 sock->sk->sk_protocol);
		return 0;
	}

	if (sock->sk->sk_state != TCP_ESTABLISHED) {
		pr_debug("not an established connection (state is %u),"
			 " use faf (listening sockets will soon be enabled)\n",
			 sock->sk->sk_state);
		return 0;
	}

	pr_debug("conditions ok for a plain socket migration\n");
	return 1;
}

int socket_file_export(struct epm_action *action, ghost_t *ghost,
		       struct task_struct *task, int index, struct file *file)
{
	int ret = 0;

	BUG_ON(action->type == EPM_CHECKPOINT);
	BUG_ON(!is_socket(file));

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
	int ret = 0;

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

