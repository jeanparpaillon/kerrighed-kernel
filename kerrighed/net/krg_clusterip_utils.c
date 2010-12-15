/*
 *  kerrighed/net/krg_clusterip.c
 *
 *  Copyright (C) 2010, Louis Rilling - Kerlabs
 */

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/namespace.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krg_clusterip.h>
#include <kddm/kddm.h>


static DEFINE_MUTEX(krgip_local_ports_ip_table_mutex);


/************** Local port functions *************/

struct krgip_local_port *krgip_local_port_alloc(__be16 num)
{
	struct krgip_local_port *port;

	port = kmalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return NULL;

	port->port = num;

	return port;
}

void krgip_local_port_free(struct krgip_local_port *port)
{
	kfree(port);
}

static void krgip_local_port_delayed_free(struct rcu_head *rcu)
{
	krgip_local_port_free(container_of(rcu, struct krgip_local_port, rcu));
}

static void krgip_local_port_free_rcu(struct krgip_local_port *port)
{
	call_rcu(&port->rcu, krgip_local_port_delayed_free);
}

void krgip_local_ports_add(struct krgip_local_ports *ports,
			   struct krgip_local_port *port,
			   struct list_head *head)
{
	spin_lock(&ports->lock);
	list_add_rcu(&port->list, head);
	spin_unlock(&ports->lock);
}

void krgip_local_ports_del(struct krgip_local_ports *ports,
			   __be16 snum,
			   struct list_head *head)
{
	struct krgip_local_port *port;

	spin_lock(&ports->lock);
	list_for_each_entry(port, head, list)
		if (port->port == snum) {
			list_del_rcu(&port->list);
			krgip_local_port_free_rcu(port);
			break;
		}
	spin_unlock(&ports->lock);
}


/*********** Established resp functions **********/

struct krgip_established_resp *krgip_established_resp_alloc(__be16 lport,
							    struct krgip_cluster_established_kddm_object *kddm_obj)
{
	struct krgip_established_resp *established;

	established = kmalloc(sizeof(*established), GFP_KERNEL);
	if (!established)
		return NULL;

	/* It would be really worrying if it happened */
	BUG_ON(!lport);
	BUG_ON(!kddm_obj);

	established->lport = lport;
	established->kddm_obj = kddm_obj;

	return established;
}

void krgip_established_resp_free(struct krgip_established_resp *established)
{
	kfree(established);
}

static void krgip_established_resp_delayed_free(struct rcu_head *rcu)
{
	krgip_established_resp_free(container_of(rcu, struct krgip_established_resp, rcu));
}

static void krgip_established_resp_free_rcu(struct krgip_established_resp *established)
{
	call_rcu(&established->rcu, krgip_established_resp_delayed_free);
}

void krgip_established_resp_add(struct krgip_local_ports *ports,
				struct krgip_established_resp *new_established)
{
	spin_lock(&ports->lock);
	list_add_rcu(&new_established->list, &ports->established_tcp_resp);
	spin_unlock(&ports->lock);
}

void krgip_established_resp_del(struct krgip_local_ports *ports, __be16 lport) {
	struct krgip_established_resp *established;

	spin_lock(&ports->lock);
	list_for_each_entry_rcu(established, &ports->established_tcp_resp, list)
		if (established->lport == lport) {
			list_del_rcu(&established->list);
			krgip_established_resp_free_rcu(established);
			break;
		}
	spin_unlock(&ports->lock);
}


/*************** Addrport functions **************/

struct krgip_addrport *krgip_addrport_alloc(__be32 daddr, __be16 dport)
{
	struct krgip_addrport *addrport;

	addrport = kmalloc(sizeof(*addrport), GFP_KERNEL);
	if (addrport) {
		addrport->daddr = daddr;
		addrport->dport = dport;
	}
	return addrport;
}

void krgip_addrport_free(struct krgip_addrport *addrport)
{
	kfree(addrport);
}


/***************** Addr functions ****************/

struct krgip_addr *krgip_addr_alloc(__be32 addr)
{
	struct krgip_addr *krg_addr;

	krg_addr = kmalloc(sizeof(*krg_addr), GFP_KERNEL);
	if (krg_addr)
		krg_addr->addr = addr;
	return krg_addr;
}

void krgip_addr_free(struct krgip_addr *addr)
{
	kfree(addr);
}



/************* Local ports functions *************/

static inline int krgip_local_ports_ip_hashfn(__be32 addr)
{
	return hash_long(addr, KRGIP_LOCAL_PORTS_IP_TABLE_BITS);
}

void krgip_local_ports_init(struct krgip_local_ports *ports)
{
	spin_lock_init(&ports->lock);
	INIT_LIST_HEAD(&ports->udp);
	INIT_LIST_HEAD(&ports->established_tcp_resp);
	INIT_LIST_HEAD(&ports->tcp);
}

struct krgip_local_ports *krgip_local_ports_find(struct netns_krgip *krgip,
						 __be32 addr)
{
	int hash = krgip_local_ports_ip_hashfn(addr);
	struct list_head *head;
	struct krgip_local_ports *ports;

	head = &krgip->local_ports_ip_table[hash];
	mutex_lock(&krgip_local_ports_ip_table_mutex);

	list_for_each_entry(ports, head, list)
		if (ports->addr == addr)
			goto out;

	ports = kmalloc(sizeof(*ports), GFP_KERNEL);
	if (!ports)
		goto out;
	krgip_local_ports_init(ports);
	ports->addr = addr;
	list_add(&ports->list, head);

out:
	mutex_unlock(&krgip_local_ports_ip_table_mutex);
	return ports;
}

static void krgip_local_ports_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct krgip_local_ports, rcu));
}

void krgip_local_ports_check_free(struct krgip_local_ports *ports)
{
	mutex_lock(&krgip_local_ports_ip_table_mutex);
	if (krgip_local_ports_empty(ports)) {
		list_del(&ports->list);
		call_rcu(&ports->rcu, krgip_local_ports_free_rcu);
	}
	mutex_unlock(&krgip_local_ports_ip_table_mutex);
}

bool krgip_local_ports_exists(struct netns_krgip *krgip, __be32 addr)
{
	int hash = krgip_local_ports_ip_hashfn(addr);
	struct list_head *head;
	struct krgip_local_ports *ports;
	bool found;

	head = &krgip->local_ports_ip_table[hash];
	mutex_lock(&krgip_local_ports_ip_table_mutex);

	found = false;
	list_for_each_entry(ports, head, list)
		if (ports->addr == addr && !krgip_local_ports_empty(ports)) {
			found = true;
			break;
		}

	mutex_unlock(&krgip_local_ports_ip_table_mutex);

	return found;
}


/*************** Tcp ports functions *************/

int
krgip_cluster_ip_tcp_get_port_prepare(struct sock *sk,
				      unsigned short snum,
				      struct krgip_cluster_ip_kddm_object **ip_obj_p,
				      struct krgip_cluster_port_kddm_object **port_obj_p,
				      struct krgip_addr **addr,
				      struct krgip_local_port **port)
{
	struct inet_sock *inet = inet_sk(sk);
	struct netns_krgip *krgip = &sock_net(sk)->krgip;
	struct kddm_set *ip_set = krgip->cluster_ips;
	struct kddm_set *port_set = krgip->cluster_ports_tcp;
	struct krgip_cluster_ip_kddm_object *ip_obj = NULL;
	struct krgip_cluster_port_kddm_object *port_obj;
	__be32 bindaddr;
	int err;

	if (!port_set
	    || sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return 0;

	bindaddr = 0;
/*	if (sk->sk_userlocks & SOCK_BINDADDR_LOCK) { */
	if (inet->saddr != 0) {
		bindaddr = inet->rcv_saddr;

		ip_obj = _kddm_get_object(ip_set, bindaddr);
		if (IS_ERR(ip_obj))
			return PTR_ERR(ip_obj);
		BUG_ON(!ip_obj);
	}

	snum = htons(snum);
	port_obj = _kddm_grab_object(port_set, snum);
	if (IS_ERR(port_obj)) {
		err = PTR_ERR(port_obj);
		goto err_put_addr;
	}
	BUG_ON(!port_obj);

	err = -EADDRINUSE;

	if (port_obj->node != KERRIGHED_NODE_ID_NONE
	    || (!ip_obj && !list_empty(&port_obj->ips))
	    || (ip_obj && ip_obj->nr_nodes && krgip_addr_find(&port_obj->ips, bindaddr)))
		goto err_put_port;

	err = -ENOMEM;
	*port = krgip_local_port_alloc(snum);
	if (!*port)
		goto err_put_port;
	if (ip_obj) {
		*addr = krgip_addr_alloc(bindaddr);
		if (!*addr) {
			krgip_local_port_free(*port);
			*port = NULL;
			goto err_put_port;
		}
	}

	*ip_obj_p = ip_obj;
	*port_obj_p = port_obj;

	return 0;

err_put_port:
	krgip_cluster_port_put_or_remove(port_set, port_obj);
err_put_addr:
	if (bindaddr)
		krgip_cluster_ip_put_or_remove(ip_set, ip_obj);

	return err;
}

void
krgip_cluster_ip_tcp_get_port_finish(struct sock *sk,
				     struct krgip_cluster_ip_kddm_object *ip_obj,
				     struct krgip_cluster_port_kddm_object *port_obj,
				     struct krgip_addr *addr,
				     struct krgip_local_port *port,
				     int error)
{
	struct netns_krgip *krgip = &sock_net(sk)->krgip;
	struct kddm_set *ip_set = krgip->cluster_ips;
	struct kddm_set *port_set = krgip->cluster_ports_tcp;
	struct kddm_set *established_set = krgip->cluster_established_tcp;
	struct krgip_cluster_established_kddm_object *established_obj;
	objid_t objid;
	struct krgip_local_ports *ports;
	int i;

	if (!port_obj)
		return;

	if (error) {
		krgip_cluster_port_put_or_remove(port_set, port_obj);
		if (ip_obj)
			krgip_cluster_ip_put_or_remove(ip_set, ip_obj);
		krgip_local_port_free(port);
		if (addr)
			krgip_addr_free(addr);
		return;
	}

	inet_sk(sk)->is_krgip = 1;

	if (!ip_obj) {
		port_obj->node = kerrighed_node_id;
		krgip_local_ports_tcp_add(&krgip->local_ports_any, port);
	} else {
		list_add(&addr->list, &port_obj->ips);
		krgip_local_ports_tcp_add(ip_obj->local_ports, port);
	}


	if (established_set) {
		/* Become owner of established objs */
		if (ip_obj) {
			objid = ((long unsigned int) ip_obj->addr << 16) + port_obj->num;
			established_obj = _kddm_grab_object(established_set, objid);
			/* owner is automatically updated */
			_kddm_put_object(established_set, objid);
		} else {
			for (i = 0; i < KRGIP_LOCAL_PORTS_IP_TABLE_SIZE; i++) {
				list_for_each_entry(ports, &krgip->local_ports_ip_table[i], list) {
					objid = ((long unsigned int) ports->addr << 16) + port_obj->num;
					established_obj = _kddm_grab_object(established_set, objid);
					_kddm_put_object(established_set, objid);
				}
			}
		}

	}

	_kddm_put_object(port_set, port_obj->num);
	if (ip_obj)
		_kddm_put_object(ip_set, ip_obj->addr);

}


void
krgip_cluster_ip_tcp_unhash_prepare(struct sock *sk,
				    struct krgip_cluster_ip_kddm_object **ip_obj_p,
				    struct krgip_cluster_port_kddm_object **port_obj_p)
{
	struct inet_sock *inet = inet_sk(sk);
	struct netns_krgip *krgip = &sock_net(sk)->krgip;
	struct kddm_set *ip_set = krgip->cluster_ips;
	struct kddm_set *port_set = krgip->cluster_ports_tcp;
	struct krgip_cluster_ip_kddm_object *ip_obj = NULL;
	struct krgip_cluster_port_kddm_object *port_obj;
	__be32 bindaddr;
	__be16 sport;

	if (!port_set
	    || !inet->is_krgip
	    || !inet->sport
	    || sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return;

	bindaddr = 0;
	if (inet->saddr != 0) {
		bindaddr = inet->rcv_saddr;

		ip_obj = _kddm_get_object(ip_set, bindaddr);
		BUG_ON(IS_ERR(ip_obj) || !ip_obj);
	}

	sport = inet->sport;
	port_obj = _kddm_grab_object(port_set, sport);
	BUG_ON(IS_ERR(port_obj) || !port_obj);

	if (!ip_obj) {
		port_obj->node = KERRIGHED_NODE_ID_NONE;
		krgip_local_ports_tcp_del(&krgip->local_ports_any, sport);
	} else {
		struct krgip_addr *addr;

		list_for_each_entry(addr, &port_obj->ips, list)
			if (addr->addr == bindaddr) {
				list_del(&addr->list);
				krgip_addr_free(addr);
				break;
			}
		krgip_local_ports_tcp_del(ip_obj->local_ports, sport);
	}

	*ip_obj_p = ip_obj;
	*port_obj_p = port_obj;
}

void
krgip_cluster_ip_tcp_unhash_finish(struct sock *sk,
				   struct krgip_cluster_ip_kddm_object *ip_obj,
				   struct krgip_cluster_port_kddm_object *port_obj)
{
	struct netns_krgip *krgip = &sock_net(sk)->krgip;

	if (!port_obj)
		return;

	krgip_cluster_port_put_or_remove(krgip->cluster_ports_tcp, port_obj);
	if (ip_obj)
		krgip_cluster_ip_put_or_remove(krgip->cluster_ips, ip_obj);
}

