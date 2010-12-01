

#include <linux/socket.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/fs_struct.h>

#include <net/tcp_states.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <kerrighed/checkpoint_sock.h>
#include "checkpoint_skbuff.h"
#include "checkpoint_ip.h"
#include "checkpoint_utils.h"


struct krgip_sockflag_mapping {
	int opt;
	int flag;
};

struct krgip_sockflag_mapping sk_flag_map[] = {
	{SO_OOBINLINE, SOCK_URGINLINE},
	{SO_KEEPALIVE, SOCK_KEEPOPEN},
	{SO_BROADCAST, SOCK_BROADCAST},
	{SO_TIMESTAMP, SOCK_RCVTSTAMP},
	{SO_TIMESTAMPNS, SOCK_RCVTSTAMPNS},
	{SO_DEBUG, SOCK_DBG},
	{SO_DONTROUTE, SOCK_LOCALROUTE},
};

struct krgip_sockflag_mapping sock_flag_map[] = {
	{SO_PASSCRED, SOCK_PASSCRED},
};


static int krgip_checkpoint_data(struct epm_action *action, ghost_t *ghost,
				 struct socket *sock)
{
	int ret = 0;
	struct sock *sk = sock->sk;

	if (KRGIP_CKPT_ISDST(action)) {
		ret = krgip_import_buffers(action, ghost, &sk->sk_receive_queue);
		if (ret)
			goto out;

		ret = krgip_import_buffers(action, ghost, &sk->sk_write_queue);
		if (ret)
			goto out;
	} else {
		ret = krgip_export_buffers(action, ghost, &sk->sk_receive_queue);
		if (ret)
			goto out;

		ret = krgip_export_buffers(action, ghost, &sk->sk_write_queue);
		if (ret)
			goto out;
	}

out:
	return ret;
}

static int krgip_checkpoint_sockflags(struct epm_action *action, ghost_t *ghost,
				      struct socket *sock)
{
	unsigned long sock_flags = sock->flags;
	unsigned long sk_flags = sock->sk->sk_flags;
	int ret = 0;
	int i;

	KRGIP_CKPT_COPY(action, ghost, sock_flags, ret);
	KRGIP_CKPT_COPY(action, ghost, sk_flags, ret);

	if (ret)
		goto out;

	if (KRGIP_CKPT_ISSRC(action))
		goto out;

	for (i = 0; i < ARRAY_SIZE(sk_flag_map); i++) {
		int opt = sk_flag_map[i].opt;
		int flag = sk_flag_map[i].flag;
		int v = 1;

		if (test_and_clear_bit(flag, &sk_flags))
			ret = kernel_setsockopt(sock, SOL_SOCKET, opt, (char *)&v, sizeof(v));

		if (ret) {
			printk("Failed to set skopt %i: %i\n", opt, ret);
			goto out;
		}
	}

	for (i = 0; i < ARRAY_SIZE(sock_flag_map); i++) {
		int opt = sock_flag_map[i].opt;
		int flag = sock_flag_map[i].flag;
		int v = 1;

		if (test_and_clear_bit(flag, &sock_flags))
			ret = kernel_setsockopt(sock, SOL_SOCKET, opt, (char *)&v, sizeof(v));

		if (ret) {
			printk("Failed to set sockopt %i: %i\n", opt, ret);
			goto out;
		}
	}

	/* TODO: Handle SOCK_TIMESTAMPING_* flags */
	if (test_bit(SOCK_TIMESTAMPING_TX_HARDWARE, &sk_flags) ||
	    test_bit(SOCK_TIMESTAMPING_TX_SOFTWARE, &sk_flags) ||
	    test_bit(SOCK_TIMESTAMPING_RX_HARDWARE, &sk_flags) ||
	    test_bit(SOCK_TIMESTAMPING_RX_SOFTWARE, &sk_flags) ||
	    test_bit(SOCK_TIMESTAMPING_SOFTWARE, &sk_flags) ||
	    test_bit(SOCK_TIMESTAMPING_RAW_HARDWARE, &sk_flags) ||
	    test_bit(SOCK_TIMESTAMPING_SYS_HARDWARE, &sk_flags)) {
		printk("SOF_TIMESTAMPING_* flags are not supported\n");
		ret = -ENOSYS;
		goto out;
	}

	if (test_and_clear_bit(SOCK_DEAD, &sk_flags))
		sock_set_flag(sock->sk, SOCK_DEAD);


	/* Anything that is still set in the flags that isn't part of
	 * our protocol's default set, indicates an error
	 */
	if (sk_flags & ~sock->sk->sk_flags) {
		printk("Unhandled sock flags: %lx\n", sk_flags);
		ret = -EINVAL;
		goto out;
	}

out:
	return ret;
}


static int krgip_checkpoint_bufopts(struct epm_action *action, ghost_t *ghost,
				    struct socket *sock)
{
	int ret = 0;

	if (KRGIP_CKPT_ISDST(action)) {
		KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_RCVBUFFORCE, u_int, ret);
		KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_SNDBUFFORCE, u_int, ret);
	} else {
		int bufsize;
		int len = sizeof(bufsize);

		ret = kernel_getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *) &bufsize, &len);
		if (ret)
			goto out;

		ret = kernel_getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *) &bufsize, &len);
		if (ret)
			goto out;

		/* It's silly that we have to fight ourselves here, but
		 * sock_setsockopt() doubles the initial value, so divide here
		 * to store the user's value and avoid doubling on restart
		 */
		if (sock->sk->sk_rcvbuf != SOCK_MIN_RCVBUF)
			sock->sk->sk_rcvbuf >>= 1;

		if (sock->sk->sk_sndbuf != SOCK_MIN_SNDBUF)
			sock->sk->sk_sndbuf >>= 1;

		KRGIP_CKPT_COPY(action, ghost, sock->sk->sk_rcvbuf, ret);
		KRGIP_CKPT_COPY(action, ghost, sock->sk->sk_sndbuf, ret);
	}

out:
	return ret;
}

static int krgip_check_state(struct socket *sock)
{
	if (sock->sk->sk_family != PF_INET) {
		printk("socket type %i is unsupported\n", sock->sk->sk_family);
		return -ENOTSUPP;
	} else if ((sock->state == SS_CONNECTED) && (sock->sk->sk_state != TCP_ESTABLISHED)) {
		printk("sock/et in inconsistent state: %i/%i\n", sock->state, sock->sk->sk_state);
		return -EINVAL;
	} else if ((sock->sk->sk_state < TCP_ESTABLISHED) || (sock->sk->sk_state >= TCP_MAX_STATES)) {
		printk("sock in invalid state: %i\n", sock->sk->sk_state);
		return -EINVAL;
	} else if (sock->state > SS_DISCONNECTING) {
		printk("socket in invalid state: %i", sock->sk->sk_state);
		return -EINVAL;
	}

	return 0;
}

static int krgip_pre_close(struct socket *sock)
{
	if (sock->sk->sk_protocol == IPPROTO_UDP)
		udp_lib_unhash(sock->sk);
	else
		return -ENOTSUPP;

	return 0;
}

static int krgip_checkpoint_sock(struct epm_action *action, ghost_t *ghost,
				 struct socket *sock)
{
	struct sock *sk = sock->sk;
	int ret = 0;
	unsigned char shutdown, userlocks, no_check, state;


	KRGIP_CKPT_COPY(action, ghost, sock->state, ret);

	KRGIP_CKPT_COPY(action, ghost, sk->sk_bound_dev_if, ret);
	KRGIP_CKPT_COPY(action, ghost, sk->sk_family, ret);
	KRGIP_CKPT_COPY(action, ghost, sk->sk_protocol, ret);
	KRGIP_CKPT_COPY(action, ghost, sk->sk_err, ret);
	KRGIP_CKPT_COPY(action, ghost, sk->sk_err_soft, ret);
	KRGIP_CKPT_COPY(action, ghost, sk->sk_type, ret);
	KRGIP_CKPT_COPY(action, ghost, sk->sk_max_ack_backlog, ret);

	/* May not be directly copied */
	if (KRGIP_CKPT_ISSRC(action)) {
		state = sk->sk_state;
		shutdown = sk->sk_shutdown;
		userlocks = sk->sk_userlocks;
		no_check = sk->sk_no_check;
	}
	KRGIP_CKPT_COPY(action, ghost, state, ret);
	KRGIP_CKPT_COPY(action, ghost, shutdown, ret);
	KRGIP_CKPT_COPY(action, ghost, userlocks, ret);
	KRGIP_CKPT_COPY(action, ghost, no_check, ret);
	if (KRGIP_CKPT_ISDST(action)) {
		sk->sk_state = state;
		sk->sk_shutdown = shutdown;
		sk->sk_userlocks = userlocks;
		sk->sk_no_check = no_check;
	}

	KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_REUSEADDR, u_int, ret);
	KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_PRIORITY, u_int, ret);
	KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_RCVLOWAT, u_int, ret);
	KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_LINGER, u_long, ret);
	KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_SNDTIMEO, struct timeval, ret);
	KRGIP_CKPT_SOCKOPT(action, ghost, sock, SO_RCVTIMEO, struct timeval, ret);

	if (ret)
		goto out;

	ret = krgip_checkpoint_bufopts(action, ghost, sock);
	if (ret)
		goto out;

	ret = krgip_checkpoint_sockflags(action, ghost, sock);
	if (ret)
		goto out;

	ret = krgip_checkpoint_data(action, ghost, sock);
	if (ret)
		goto out;

out:
	return ret;
}


int krgip_export_sock(struct epm_action *action, ghost_t *ghost, struct socket *sock)
{
	int ret = 0;

	sock_hold(sock->sk);

	ret = krgip_check_state(sock);
	if (ret)
		goto out;

	ret = krgip_pre_close(sock);
	if (ret)
		goto out;

	ret = krgip_checkpoint_sock(action, ghost, sock);
	if (ret)
		goto out;

	ret = krgip_export_ip(action, ghost, sock);
	if (ret)
		goto out;

	sock_orphan(sock->sk);
out:
	sock_put(sock->sk);
	sock->sk = NULL;

	if (ret)
		pr_debug("export_sock() returned error %d\n", ret);
	return ret;
}

int krgip_import_sock(struct epm_action *action, ghost_t *ghost, struct socket *sock)
{

	int ret = 0;

	sock_hold(sock->sk);

	ret = krgip_checkpoint_sock(action, ghost, sock);
	if (ret)
		goto out_err;

	if (sock->sk->sk_family != PF_INET) {
		ret = -ENOTSUPP;
		goto out_err;
	}

	ret = krgip_import_ip(action, ghost, sock);
	if (ret)
		goto out_err;

	ret = krgip_check_state(sock);
	if (ret)
		goto out_err;

	sock_put(sock->sk);

	return 0;

out_err:
	sock_orphan(sock->sk);
	sock_put(sock->sk);
	sock->sk = NULL;
	pr_debug("import_sock() returned error %d\n", ret);
	return ret;

}

