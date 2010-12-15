/*
 *  kerrighed/net/checkpoint_tcp.c
 *
 *  Copyright (C) 2010, Emmanuel Thierry - Kerlabs
 *
 *  Adapted from Linux-CR project [https://ckpt.wiki.kernel.org]
 */

#include <linux/net.h>
#include <linux/tcp.h>

#include <net/inet_sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_common.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/ip.h>

#include <kerrighed/krg_clusterip.h>
#include <kerrighed/socket_file_mgr.h>
#include <kerrighed/namespace.h>

#include "checkpoint_tcp.h"
#include "checkpoint_utils.h"


static void krgip_bind_hash(struct sock *sk)
{
	struct inet_bind_hashbucket *head;
	struct inet_bind_bucket *bucket;
        struct krg_namespace *krg_ns;
	struct net *net;

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);
	net = krg_ns->root_nsproxy.net_ns;
	put_krg_ns(krg_ns);

	head = &tcp_hashinfo.bhash[inet_bhashfn(net, inet_sk(sk)->num, tcp_hashinfo.bhash_size)];
	bucket = inet_bind_bucket_create(tcp_hashinfo.bind_bucket_cachep,
					 net, head, inet_sk(sk)->num);

	if (bucket) {
		inet_bind_hash(sk, bucket, inet_sk(sk)->num);
		pr_debug("bound on %d\n", inet_sk(sk)->num);
	}
}

static struct sock *krgip_get_parent_sock(struct sock *sk)
{
	struct krg_namespace *krg_ns;
	struct sock *parent;

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);

	parent = __inet_lookup_listener(krg_ns->root_nsproxy.net_ns, &tcp_hashinfo,
					inet_sk(sk)->saddr, htons(inet_sk(sk)->sport),
					sk->sk_bound_dev_if);

	put_krg_ns(krg_ns);

	return parent;
}

static int krgip_checkpoint_tcp(struct epm_action *action, ghost_t *ghost,
			       struct socket *sock)
{
	int ret = 0;
	struct inet_connection_sock *icsk = inet_csk(sock->sk);
	struct tcp_sock* tcp = tcp_sk(sock->sk);
	unsigned int now = tcp_timestamp, abs_time;

	if (KRGIP_CKPT_ISSRC(action)) {
		abs_time = now + sock->sk->sk_krgip_time_delta;
	}
	KRGIP_CKPT_COPY(action, ghost, abs_time, ret);
	if (KRGIP_CKPT_ISDST(action)) {
		sock->sk->sk_krgip_time_delta = abs_time - now;
	}

	KRGIP_CKPT_COPY(action, ghost, tcp->tcp_header_len, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->xmit_size_goal_segs, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->pred_flags, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->rcv_nxt, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->copied_seq, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->rcv_wup, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_nxt, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->snd_una, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_sml, ret);
	KRGIP_CKPT_TSTAMP(action, ghost, tcp->rcv_tstamp, now, ret);
	KRGIP_CKPT_TSTAMP(action, ghost, tcp->lsndtime, now, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->snd_wl1, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_wnd, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->max_window, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->mss_cache, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->window_clamp, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->rcv_ssthresh, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->frto_highmark, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->advmss, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->frto_counter, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->nonagle, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->srtt, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->mdev, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->mdev_max, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->rttvar, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->rtt_seq, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->packets_out, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->retrans_out, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->urg_data, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->ecn_flags, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->reordering, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_up, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->keepalive_probes, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->rx_opt, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->snd_ssthresh, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_cwnd, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_cwnd_cnt, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_cwnd_clamp, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->snd_cwnd_used, ret);
	KRGIP_CKPT_TSTAMP(action, ghost, tcp->snd_cwnd_stamp, now, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->rcv_wnd, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->write_seq, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->pushed_seq, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->lost_out, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->sacked_out, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->fackets_out, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->tso_deferred, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->bytes_acked, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->lost_cnt_hint, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->retransmit_high, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->lost_retrans_low, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->prior_ssthresh, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->high_seq, ret);

	KRGIP_CKPT_TSTAMP(action, ghost, tcp->retrans_stamp, now, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->undo_marker, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->undo_retrans, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->total_retrans, ret);

	KRGIP_CKPT_COPY(action, ghost, tcp->urg_seq, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->keepalive_time, ret);
	KRGIP_CKPT_COPY(action, ghost, tcp->keepalive_intvl, ret);

	KRGIP_CKPT_TSTAMP(action, ghost, icsk->icsk_timeout, now, ret);
	KRGIP_CKPT_TSTAMP(action, ghost, icsk->icsk_ack.timeout, now, ret);
	KRGIP_CKPT_TSTAMP(action, ghost, icsk->icsk_ack.lrcvtime, now, ret);

	if (ret)
		goto out;


	if (!skb_queue_empty(&tcp->ucopy.prequeue))
		pr_debug("Prequeue isn't empty\n");

out:
	return ret;
}


int krgip_export_tcp(struct epm_action *action, ghost_t *ghost, struct socket *sock)
{
	int ret;

	BUG_ON(!sock->sk);
	BUG_ON(sock->sk->sk_protocol != IPPROTO_TCP);

	/* We don't want sock_release() neither tcp_close() to do this job,
	 * because they will acknoledge the counterpart of the end of the
	 * connection. Just do the necessary cleanup here : unhash ports from
	 * kerrighed objects and system tables. */
	/*inet_unhash(sock->sk);*/

	local_bh_disable();
	tcp_set_state(sock->sk, TCP_CLOSE);
	local_bh_enable();

	ret = krgip_checkpoint_tcp(action, ghost, sock);
	if (ret)
		goto out;

out:
	if (ret)
		pr_debug("export_tcp() returned error %d\n", ret);
	return ret;
}

int krgip_import_tcp(struct epm_action *action, ghost_t *ghost, struct socket *sock)
{
	struct inet_sock *inet = inet_sk(sock->sk);
	struct inet_connection_sock *icsk = inet_csk(sock->sk);
	struct sockaddr_in bindaddr = {
		.sin_family = AF_INET,
		.sin_addr = {inet->saddr},
		.sin_port = inet->sport
	};
	struct sock *parent;
	int ret;

	BUG_ON(!sock->sk);
	BUG_ON(sock->sk->sk_protocol != IPPROTO_TCP);


	ret = krgip_checkpoint_tcp(action, ghost, sock);
	if (ret)
		goto out;

	sock->sk->sk_gso_type = SKB_GSO_TCPV4;

	if (inet->sport) {
		pr_debug("tcp binding on %d.%d.%d.%d:%d <=> %d.%d.%d.%d:%d\n",
			 SPLIT_IP4_ADDR(inet->saddr),
			 ntohs(inet->sport),
			 SPLIT_IP4_ADDR(inet->daddr),
			 ntohs(inet->dport));

		if (sock->sk->sk_state == TCP_ESTABLISHED) {
			inet->num = ntohs(inet->sport);
			parent = krgip_get_parent_sock(sock->sk);
			if (parent) {
				inet_hash(sock->sk);

				local_bh_disable();
				__inet_inherit_port(parent, sock->sk);
				local_bh_enable();
				pr_debug("inherited port\n");
			} else {
				local_bh_disable();
				krgip_bind_hash(sock->sk);
				local_bh_enable();
				inet_hash(sock->sk);
			}
		} else if (sock->sk->sk_state == TCP_CLOSE || sock->sk->sk_state == TCP_LISTEN) {
			sock->sk->sk_reuse = 2;
			inet->freebind = 1;
			inet->num = 0;

			if (sock->sk->sk_state == TCP_LISTEN) {
				sock->sk->sk_state = TCP_CLOSE;
				ret = inet_bind(sock, (struct sockaddr*) &bindaddr, sizeof(bindaddr));
				if (!ret)
					ret = inet_listen(sock, sock->sk->sk_max_ack_backlog);
			} else {
				ret = inet_bind(sock, (struct sockaddr*) &bindaddr, sizeof(bindaddr));
			}
		}
	}

	if (ret)
		goto out;

	/*tcp_send_ack(sock->sk);*/
	/*tcp_write_wakeup(sock->sk);*/
	tcp_push_pending_frames(sock->sk);
	inet_csk_reset_xmit_timer(sock->sk, ICSK_TIME_RETRANS,
				  icsk->icsk_timeout - tcp_timestamp, TCP_RTO_MAX);
	inet_csk_reset_xmit_timer(sock->sk, ICSK_TIME_DACK,
				  icsk->icsk_ack.timeout - tcp_timestamp, TCP_RTO_MAX);

out:
	if (ret)
		pr_debug("import_tcp() returned error %d\n", ret);
	return ret;
}
