#include <linux/in.h>
#include <linux/namei.h>
#include <linux/net.h>

#include <net/inet_connection_sock.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "../../net/ipv4/udp_impl.h"
#include "checkpoint_ip.h"
/*#include "checkpoint_tcp.h"*/
#include "checkpoint_utils.h"

static int krgip_checkpoint_ip(struct epm_action *action, ghost_t *ghost,
			       struct socket *sock)
{
	struct inet_sock *inet = inet_sk(sock->sk);
	struct inet_connection_sock *icsk = inet_csk(sock->sk);
	int ret = 0;

	KRGIP_CKPT_COPY(action, ghost, inet->saddr, ret);
	KRGIP_CKPT_COPY(action, ghost, inet->sport, ret);
	KRGIP_CKPT_COPY(action, ghost, inet->daddr, ret);
	KRGIP_CKPT_COPY(action, ghost, inet->dport, ret);
	KRGIP_CKPT_COPY(action, ghost, inet->rcv_saddr, ret);
	KRGIP_CKPT_COPY(action, ghost, inet->num, ret);

	KRGIP_CKPT_COPY(action, ghost, inet->uc_ttl, ret);
	KRGIP_CKPT_COPY(action, ghost, inet->cmsg_flags, ret);

	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.pending, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.quick, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.pingpong, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.blocked, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.ato, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.timeout, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.lrcvtime, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.last_seg_size, ret);
	KRGIP_CKPT_COPY(action, ghost, icsk->icsk_ack.rcv_mss, ret);

	if (ret)
		goto out;

	if (sock->sk->sk_protocol == IPPROTO_TCP) {
		/* ret = krgip_checkpoint_tcp(action, ghost, sock); */
	} else if (sock->sk->sk_protocol == IPPROTO_UDP) {
		ret = 0;
	} else {
		ret = -EINVAL;
		printk("unknown socket protocol %d\n", sock->sk->sk_protocol);
	}

out:
	return ret;
}

#if 0
static int krgip_checkpoint_sin(struct epm_action *action, ghost_t *ghost, struct sockaddr_in *sockaddr)
{
	int ret = 0;

	KRGIP_CKPT_COPY(action, ghost, *sockaddr, ret);

	return ret;
}
#endif

int krgip_export_ip(struct epm_action *action, ghost_t *ghost, struct socket *sock)
{
	int ret;

	ret = krgip_checkpoint_ip(action, ghost, sock);
	if (ret)
		goto out;

out:
	if (ret)
		pr_debug("export_ip() returned error %d\n", ret);
	return ret;
}

int krgip_import_ip(struct epm_action *action, ghost_t *ghost, struct socket *sock)
{
/*	struct sockaddr_in peeraddr = {
		.sin_family = AF_INET,
		.sin_addr = {inet_sk(sock->sk)->daddr},
		.sin_port = inet_sk(sock->sk)->dport
	};*/
	int ret = 0;


	ret = krgip_checkpoint_ip(action, ghost, sock);
	if (ret)
		goto out;

	if (inet_sk(sock->sk)->sport) {
		if (sock->sk->sk_state == TCP_CLOSE || sock->sk->sk_state == TCP_LISTEN) {
			sock->sk->sk_reuse = 2;
			inet_sk(sock->sk)->freebind = 1;
		}

		if (KRGIP_CKPT_ISDST(action))
			sock->sk->sk_gso_type = SKB_GSO_UDP;

		pr_debug("binding on %d.%d.%d.%d:%d <=> %d.%d.%d.%d:%d\n",
			 SPLIT_IP4_ADDR(inet_sk(sock->sk)->saddr),
			 ntohs(inet_sk(sock->sk)->sport),
			 SPLIT_IP4_ADDR(inet_sk(sock->sk)->daddr),
			 ntohs(inet_sk(sock->sk)->dport));

		pr_debug("binding on %d\n", htons(inet_sk(sock->sk)->sport));
		ret = udp_v4_get_port(sock->sk, htons(inet_sk(sock->sk)->sport));
		if (ret)
			goto out;
		pr_debug("bound on %d\n", htons(inet_sk(sock->sk)->sport));

/*
		if (sock->sk->sk_state == TCP_ESTABLISHED) {
			pr_debug("binding on %d\n", htons(inet_sk(sock->sk)->sport));
			ret = ip4_datagram_connect(sock->sk, (struct sockaddr *) &peeraddr, sizeof(peeraddr));
*/
/*

		ret = sock->ops->bind(sock, (struct sockaddr *) &bindaddr, sizeof(bindaddr));
		if (ret < 0) {
			pr_debug("bind failed with errno %d\n", ret);
			goto out;
		}

		if (peeraddr.sin_port) {
			pr_debug("connecting to %d.%d.%d.%d:%d",
				 SPLIT_IP4_ADDR((peeraddr.sin_addr.s_addr)),
				 ntohs(peeraddr.sin_port));

			ret = sock->ops->connect(sock, (struct sockaddr *) &peeraddr, sizeof(peeraddr), sock->file->f_flags);
			if (ret < 0) {
				pr_debug("connect failed with errno %d\n", ret);
				goto out;
			}
		}
*/
	}

	/* ret = krgip_checkpoint_data_ip(action, ghost, sock); */

out:
	if (ret)
		pr_debug("import_ip() returned error %d\n", ret);
	return ret;
}
