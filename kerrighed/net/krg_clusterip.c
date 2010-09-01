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
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/namespace.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krg_clusterip.h>
#include <kddm/kddm.h>

enum {
	KRGIP_LOCAL_PORTS_IP_TABLE_BITS = 8,
	KRGIP_LOCAL_PORTS_IP_TABLE_SIZE = 1 << KRGIP_LOCAL_PORTS_IP_TABLE_BITS,
};

static DEFINE_MUTEX(krgip_local_ports_ip_table_mutex);

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

static inline int krgip_local_ports_ip_hashfn(__be32 addr)
{
	return hash_long(addr, KRGIP_LOCAL_PORTS_IP_TABLE_BITS);
}

static void krgip_local_ports_init(struct krgip_local_ports *ports)
{
	spin_lock_init(&ports->lock);
	INIT_LIST_HEAD(&ports->udp);
	INIT_LIST_HEAD(&ports->tcp);
}

static
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

static void krgip_local_ports_check_free(struct krgip_local_ports *ports)
{
	mutex_lock(&krgip_local_ports_ip_table_mutex);
	if (krgip_local_ports_empty(ports)) {
		list_del(&ports->list);
		call_rcu(&ports->rcu, krgip_local_ports_free_rcu);
	}
	mutex_unlock(&krgip_local_ports_ip_table_mutex);
}

static bool krgip_local_ports_exists(struct netns_krgip *krgip, __be32 addr)
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

static int krgip_cluster_ip_alloc_object(struct kddm_obj *obj_entry,
					 struct kddm_set *set,
					 objid_t objid)
{
	struct krg_namespace *krg_ns;
	struct krgip_cluster_ip_kddm_object *obj;
	__be32 addr = objid;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);
	obj->local_ports = krgip_local_ports_find(&krg_ns->root_nsproxy.net_ns->krgip, addr);
	put_krg_ns(krg_ns);
	if (!obj->local_ports) {
		kfree(obj);
		return -ENOMEM;
	}
	obj->addr = addr;

	obj_entry->object = obj;
	return 0;
}

static int krgip_cluster_ip_first_touch(struct kddm_obj *obj_entry,
					struct kddm_set *set,
					objid_t objid,
					int flags)
{
	struct krgip_cluster_ip_kddm_object *obj;
	int err;

	err = krgip_cluster_ip_alloc_object(obj_entry, set, objid);
	if (err)
		return err;

	obj = obj_entry->object;
	obj->nr_nodes = 0;

	return err;
}

static int krgip_cluster_ip_remove_object(void *object,
					  struct kddm_set *set,
					  objid_t objid)
{
	struct krgip_cluster_ip_kddm_object *obj = object;

	krgip_local_ports_check_free(obj->local_ports);
	kfree(obj);

	return 0;
}

static int krgip_cluster_ip_import_object(struct rpc_desc *desc,
					  struct kddm_set *set,
					  struct kddm_obj *obj_entry,
					  objid_t objid,
					  int flags)
{
	struct krgip_cluster_ip_kddm_object *obj = obj_entry->object;
	int nr_nodes;
	int err;

	err = rpc_unpack_type(desc, nr_nodes);
	if (err)
		return err;

	obj->nr_nodes = nr_nodes;
	return err;
}

static int krgip_cluster_ip_export_object(struct rpc_desc *desc,
					  struct kddm_set *set,
					  struct kddm_obj *obj_entry,
					  objid_t objid,
					  int flags)
{
	struct krgip_cluster_ip_kddm_object *obj = obj_entry->object;

	return rpc_pack_type(desc, obj->nr_nodes);
}

static struct iolinker_struct krgip_cluster_ip_io_linker = {
	.first_touch = krgip_cluster_ip_first_touch,
	.alloc_object = krgip_cluster_ip_alloc_object,
	.remove_object = krgip_cluster_ip_remove_object,
	.export_object = krgip_cluster_ip_export_object,
	.import_object = krgip_cluster_ip_import_object,
	.linker_name = "cluster_ip",
};

static
int handle_cluster_ip_unused(struct rpc_desc *desc, void *msg, size_t size)
{
	__be32 addr = *(__be32 *)msg;
	struct krg_namespace *krg_ns;
	int err = 0;

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);
	if (krgip_local_ports_exists(&krg_ns->root_nsproxy.net_ns->krgip, addr))
		err = -EADDRINUSE;
	put_krg_ns(krg_ns);

	return err;
}

int krgip_cluster_ip_unused(__be32 addr)
{
	struct rpc_desc *desc;
	krgnodemask_t nodes;
	kerrighed_node_t node;
	int err = 0;

	membership_online_hold();
	if (!krgnode_online(kerrighed_node_id))
		goto out;

	err = -ENOMEM;
	krgnodes_copy(nodes, krgnode_online_map);
	desc = rpc_begin_m(CLUSTER_IP_UNUSED, &nodes);
	if (!desc)
		goto out;

	err = rpc_pack_type(desc, addr);
	if (err)
		goto out_end;

	for_each_krgnode_mask(node, nodes) {
		if (rpc_unpack_type_from(desc, node, err))
			err = -EPIPE;
		if (err)
			goto out_end;
	}

out_end:
	rpc_end(desc, 0);

out:
	membership_online_release();
	return err;
}
EXPORT_SYMBOL(krgip_cluster_ip_unused);

void krgip_cluster_ip_put_or_remove(struct kddm_set *set,
				    struct krgip_cluster_ip_kddm_object *obj)
{
	if (obj->nr_nodes)
		_kddm_put_object(set, obj->addr);
	else
		_kddm_remove_frozen_object(set, obj->addr);
}
EXPORT_SYMBOL(krgip_cluster_ip_put_or_remove);

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

static int krgip_cluster_port_alloc_object(struct kddm_obj *obj_entry,
					   struct kddm_set *set,
					   objid_t objid)
{
	struct krgip_cluster_port_kddm_object *obj;
	__be16 num = objid;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	INIT_LIST_HEAD(&obj->ips);
	obj->num = num;

	obj_entry->object = obj;
	return 0;
}

static int krgip_cluster_port_first_touch(struct kddm_obj *obj_entry,
					  struct kddm_set *set,
					  objid_t objid,
					  int flags)
{
	struct krgip_cluster_port_kddm_object *obj;
	int err;

	err = krgip_cluster_port_alloc_object(obj_entry, set, objid);
	if (err)
		return err;

	obj = obj_entry->object;
	obj->node = KERRIGHED_NODE_ID_NONE;

	return err;
}

static int krgip_cluster_port_remove_object(void *object,
					    struct kddm_set *set,
					    objid_t objid)
{
	struct krgip_cluster_port_kddm_object *obj = object;
	struct krgip_addr *addr, *safe;

	list_for_each_entry_safe(addr, safe, &obj->ips, list) {
		list_del(&addr->list);
		krgip_addr_free(addr);
	}

	kfree(obj);

	return 0;
}

static int krgip_cluster_port_import_object(struct rpc_desc *desc,
					    struct kddm_set *set,
					    struct kddm_obj *obj_entry,
					    objid_t objid,
					    int flags)
{
	struct krgip_cluster_port_kddm_object *obj = obj_entry->object;
	kerrighed_node_t node;
	LIST_HEAD(tmp);
	LIST_HEAD(to_free);
	struct krgip_addr *krg_addr, *safe;
	__be32 addr;
	int err;

	err = rpc_unpack_type(desc, node);
	if (err)
		return err;

	for (;;) {
		err = rpc_unpack_type(desc, addr);
		if (err)
			goto out_free;
		if (!addr)
			break;

		err = -ENOMEM;
		krg_addr = krgip_addr_alloc(addr);
		if (!krg_addr)
			goto out_free;
		list_add(&krg_addr->list, &tmp);
	}

	obj->node = node;
	list_splice_init(&obj->ips, &to_free);
	list_splice_init(&tmp, &obj->ips);

	list_splice(&to_free, &tmp);
out_free:
	list_for_each_entry_safe(krg_addr, safe, &tmp, list) {
		list_del(&krg_addr->list);
		krgip_addr_free(krg_addr);
	}

	return err;
}

static int krgip_cluster_port_export_object(struct rpc_desc *desc,
					    struct kddm_set *set,
					    struct kddm_obj *obj_entry,
					    objid_t objid,
					    int flags)
{
	struct krgip_cluster_port_kddm_object *obj = obj_entry->object;
	struct krgip_addr *addr;
	__be32 null_addr;
	int err;

	err = rpc_pack_type(desc, obj->node);
	if (err)
		return err;

	list_for_each_entry(addr, &obj->ips, list) {
		err = rpc_pack_type(desc, addr->addr);
		if (err)
			return err;
	}

	null_addr = 0;
	err = rpc_pack_type(desc, null_addr);

	return err;
}

static struct iolinker_struct krgip_cluster_port_io_linker = {
	.first_touch = krgip_cluster_port_first_touch,
	.alloc_object = krgip_cluster_port_alloc_object,
	.remove_object = krgip_cluster_port_remove_object,
	.export_object = krgip_cluster_port_export_object,
	.import_object = krgip_cluster_port_import_object,
	.linker_name = "cluster_port",
};

void
krgip_cluster_port_put_or_remove(struct kddm_set *set,
				 struct krgip_cluster_port_kddm_object *obj)
{
	if (!list_empty(&obj->ips)
	    || obj->node != KERRIGHED_NODE_ID_NONE)
		_kddm_put_object(set, obj->num);
	else
		_kddm_remove_frozen_object(set, obj->num);
}

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

	printk("%d(%s) %s: enter sk=0x%p\n", current->pid, current->comm, __PRETTY_FUNCTION__,
		sk);

	if (!port_set
	    || sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return 0;

	bindaddr = 0;
	if (sk->sk_userlocks & SOCK_BINDADDR_LOCK) {
		bindaddr = inet->rcv_saddr;

		ip_obj = _kddm_get_object(ip_set, bindaddr);
		if (IS_ERR(ip_obj))
			return PTR_ERR(ip_obj);
		BUG_ON(!ip_obj);
	}
	printk("%d(%s) %s: bindaddr=%x\n", current->pid, current->comm, __PRETTY_FUNCTION__,
		ntohl(bindaddr));

	snum = htons(snum);
	port_obj = _kddm_grab_object(port_set, snum);
	if (IS_ERR(port_obj)) {
		err = PTR_ERR(port_obj);
		goto err_put_addr;
	}
	BUG_ON(!port_obj);
	printk("%d(%s) %s: snum=%hd\n", current->pid, current->comm, __PRETTY_FUNCTION__,
		ntohs(snum));

	err = -EADDRINUSE;
	if (port_obj->node != KERRIGHED_NODE_ID_NONE
	    || (!ip_obj && !list_empty(&port_obj->ips))
	    || (ip_obj && ip_obj->nr_nodes
		&& krgip_addr_find(&port_obj->ips, bindaddr)))
			goto err_put_port;
	printk("%d(%s) %s: available\n", current->pid, current->comm, __PRETTY_FUNCTION__);

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
	printk("%d(%s) %s: done\n", current->pid, current->comm, __PRETTY_FUNCTION__);

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

	if (!port_obj)
		return;

	printk("%d(%s) %s: enter sk=0x%p\n", current->pid, current->comm, __PRETTY_FUNCTION__,
		sk);
	if (error) {
		printk("%d(%s) %s: error\n", current->pid, current->comm, __PRETTY_FUNCTION__);
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

	_kddm_put_object(port_set, port_obj->num);
	if (ip_obj)
		_kddm_put_object(ip_set, ip_obj->addr);
	printk("%d(%s) %s: done\n", current->pid, current->comm, __PRETTY_FUNCTION__);
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

	printk("%d(%s) %s: enter sk=0x%p num=%d\n", current->pid, current->comm, __PRETTY_FUNCTION__,
		sk, inet->num);
	if (!port_set
	    || !inet->is_krgip
	    || !inet->sport
	    || sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return;

	bindaddr = 0;
	if (sk->sk_userlocks & SOCK_BINDADDR_LOCK) {
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
	printk("%d(%s) %s: done bindaddr=%x sport=%hd\n", current->pid, current->comm, __PRETTY_FUNCTION__,
		ntohl(bindaddr), ntohs(sport));
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

static int netns_krgip_init(struct net *net)
{
	struct netns_krgip *krgip = &net->krgip;
	struct kddm_set *set;
	int i;

	if (!current->create_krg_ns) {
		krgip->cluster_ips = NULL;
		krgip->cluster_ports_udp = NULL;
		krgip->cluster_ports_tcp = NULL;
		return 0;
	}

	set = create_new_kddm_set(kddm_def_ns, CLUSTER_IP_KDDM_ID,
				  CLUSTER_IP_LINKER,
				  KDDM_RR_DEF_OWNER,
				  0,
				  KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(set))
		goto err_ips;
	krgip->cluster_ips = set;

	set = create_new_kddm_set(kddm_def_ns, CLUSTER_PORT_UDP_KDDM_ID,
				  CLUSTER_PORT_LINKER,
				  KDDM_RR_DEF_OWNER,
				  0,
				  KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(set))
		goto err_udp;
	krgip->cluster_ports_udp = set;

	set = create_new_kddm_set(kddm_def_ns, CLUSTER_PORT_TCP_KDDM_ID,
				  CLUSTER_PORT_LINKER,
				  KDDM_RR_DEF_OWNER,
				  0,
				  KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(set))
		goto err_tcp;
	krgip->cluster_ports_tcp = set;

	set = ERR_PTR(-ENOMEM);
	krgip->local_ports_ip_table = kmalloc(sizeof(*krgip->local_ports_ip_table) * KRGIP_LOCAL_PORTS_IP_TABLE_SIZE, GFP_KERNEL);
	if (!krgip->local_ports_ip_table)
		goto err_ports_table;
	for (i = 0; i < KRGIP_LOCAL_PORTS_IP_TABLE_SIZE; i++)
		INIT_LIST_HEAD(&krgip->local_ports_ip_table[i]);

	krgip_local_ports_init(&krgip->local_ports_any);

	return 0;

err_ports_table:
	_destroy_kddm_set(krgip->cluster_ports_tcp);
err_tcp:
	_destroy_kddm_set(krgip->cluster_ports_udp);
err_udp:
	_destroy_kddm_set(krgip->cluster_ips);
err_ips:
	return PTR_ERR(set);
}

static void netns_krgip_exit(struct net *net)
{
	struct netns_krgip *krgip = &net->krgip;

	if (krgip->cluster_ips) {
		kfree(krgip->local_ports_ip_table);

		_destroy_kddm_set(krgip->cluster_ports_tcp);
		_destroy_kddm_set(krgip->cluster_ports_udp);
		_destroy_kddm_set(krgip->cluster_ips);
	}
}

static struct pernet_operations krgip_cluster_ip_subsys = {
	.init = netns_krgip_init,
	.exit = netns_krgip_exit,
};

int krgip_cluster_ip_start(void)
{
	int err;

	register_io_linker(CLUSTER_IP_LINKER, &krgip_cluster_ip_io_linker);
	register_io_linker(CLUSTER_PORT_LINKER, &krgip_cluster_port_io_linker);

	err = rpc_register_int(CLUSTER_IP_UNUSED, handle_cluster_ip_unused, 0);
	if (err)
		panic("Kerrighed: Could not register RPC handler CLUSTER_IP_UNUSED!\n");

	err = register_pernet_subsys(&krgip_cluster_ip_subsys);
	if (err)
		panic("Kerrighed: Could not register cluster_ip subsys!\n");

	return err;
}
