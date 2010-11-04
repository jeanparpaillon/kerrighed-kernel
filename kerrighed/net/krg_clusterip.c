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

struct krgip_established *krgip_established_alloc(__be16 lport, __be32 addr, __be16 port)
{
	struct krgip_established *established;

	established = kmalloc(sizeof(*established), GFP_KERNEL);
	if (!established)
		return NULL;

	/* It would be really worrying if it happened */
	BUG_ON(!lport);
	BUG_ON(!addr);
	BUG_ON(!port);

	established->lport = lport;
	established->daddr = addr;
	established->dport = port;

	return established;
}

void krgip_established_free(struct krgip_established *established)
{
	kfree(established);
}

static void krgip_established_delayed_free(struct rcu_head *rcu)
{
	krgip_established_free(container_of(rcu, struct krgip_established, rcu));
}

static void krgip_established_free_rcu(struct krgip_established *established)
{
	call_rcu(&established->rcu, krgip_established_delayed_free);
}

void krgip_local_ports_add(struct krgip_local_ports *ports,
			   struct krgip_local_port *port,
			   struct list_head *head)
{
	spin_lock(&ports->lock);
	list_add_rcu(&port->list, head);
	spin_unlock(&ports->lock);

	pr_debug("added port %d\n", ntohs(port->port));
}

void krgip_local_ports_del(struct krgip_local_ports *ports,
			   __be16 snum,
			   struct list_head *head)
{
	bool deleted = 0;
	struct krgip_local_port *port;

	spin_lock(&ports->lock);
	list_for_each_entry(port, head, list)
		if (port->port == snum) {
			list_del_rcu(&port->list);
			krgip_local_port_free_rcu(port);
			pr_debug("deleted port %d\n", ntohs(snum));
			deleted = 1;
			break;
		} else {
			pr_debug("port %d (untranslated) doesn't match with port %d (untranslated)\n", port->port, snum);
		}
	spin_unlock(&ports->lock);

	if(!deleted)
		pr_debug("can't find port %d for deletion\n", ntohs(snum));
}

/* =============== deprecated =================== */
void krgip_established_add(struct krgip_local_ports *ports,
			   struct krgip_established *new_established)
{
/*	struct krgip_established *established = (struct krgip_established *) &ports->established_tcp;*/

	spin_lock(&ports->lock);
	list_add_rcu(&new_established->list, &ports->established_tcp);
	spin_unlock(&ports->lock);

	pr_debug("added established connection : me:%u <=> %u.%u.%u.%u:%u\n",
		 ntohs(new_established->lport),
		 SPLIT_IP4_ADDR(new_established->daddr),
		 ntohs(new_established->dport));
}

/* deprecated */
void krgip_established_del(struct krgip_local_ports *ports,
			   __be16 lport,
			   __be32 addr,
			   __be16 port) {
	struct krgip_established *established;

	spin_lock(&ports->lock);
	list_for_each_entry_rcu(established, &ports->established_tcp, list)
		if (established->lport == lport && established->daddr == addr
		    && established->dport == port) {

			pr_debug("deleted established connection : me:%u <=> %u.%u.%u.%u:%u\n",
				 ntohs(established->lport),
				 SPLIT_IP4_ADDR(established->daddr),
				 ntohs(established->dport));

			list_del_rcu(&established->list);
			krgip_established_free_rcu(established);
			break;
		}
	spin_unlock(&ports->lock);
}
/* =============== /deprecated =================== */


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

static inline int krgip_local_ports_ip_hashfn(__be32 addr)
{
	return hash_long(addr, KRGIP_LOCAL_PORTS_IP_TABLE_BITS);
}

static void krgip_local_ports_init(struct krgip_local_ports *ports)
{
	spin_lock_init(&ports->lock);
	INIT_LIST_HEAD(&ports->udp);
	INIT_LIST_HEAD(&ports->established_tcp); /* deprecated */
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


static
int krgip_cluster_do_delete_established(struct kddm_set *established_set,
					__be32 laddr, __be16 lport, __be32 daddr, __be16 dport)
{
	objid_t objid;
	struct krgip_cluster_established_kddm_object *established_obj;
	struct krgip_addrport *todel;
	int err = -EIO;


	objid = (laddr << 16) + lport;
	established_obj = _kddm_grab_object(established_set, objid);
	if (!established_obj)
		goto out;

	todel = krgip_addrport_find(&established_obj->established, daddr, dport);
	if (todel) {
		err = 0;
		list_del(&todel->list);

		pr_debug("established entry deleted locally :\n"
			 "%u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
			 SPLIT_IP4_ADDR(laddr),
			 ntohs(lport),
			 SPLIT_IP4_ADDR(daddr),
			 ntohs(dport));
	}

	_kddm_put_object(established_set, objid);

out:
	return err;
}

static
int handle_cluster_delete_established(struct rpc_desc *desc, void *msg, size_t size)
{
	__be32 laddr = 0;
	__be16 lport = 0;
	__be32 daddr = 0;
	__be16 dport = 0;
	struct krg_namespace *krg_ns;
	struct netns_krgip *krgip;
	struct kddm_set *established_set;
	int err = -EIO;


	if (size == sizeof(laddr) + sizeof(lport) + sizeof(daddr) + sizeof(dport)) {
		laddr = *(__be32*) msg;
		msg += sizeof(laddr);

		lport = *(__be16*) msg;
		msg += sizeof(lport);

		daddr = *(__be32*) msg;
		msg += sizeof(daddr);

		dport = *(__be16*) msg;

		pr_debug("rpc request for this established entry to be deleted :\n"
			 "%u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
			 SPLIT_IP4_ADDR(laddr),
			 ntohs(lport),
			 SPLIT_IP4_ADDR(daddr),
			 ntohs(dport));


		krg_ns = find_get_krg_ns();
		BUG_ON(!krg_ns);

		krgip = &krg_ns->root_nsproxy.net_ns->krgip;
		if (!krgip)
			goto out;

		established_set = krgip->cluster_established_tcp;
		if (established_set)
			err = krgip_cluster_do_delete_established(established_set, laddr, lport, daddr, dport);

		put_krg_ns(krg_ns);
	} else {
		pr_debug("bad rpc request for an established entry deletion\n");
	}

out:
	return err;
}

static
int krgip_cluster_rpc_delete_established(kerrighed_node_t owner, __be32 laddr, __be16 lport, __be32 daddr, __be16 dport)
{
	struct rpc_desc *desc;
	int err = -EIO;

	pr_debug("ask to node %u to delete established entry :\n"
		 "%u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
		 owner,
		 SPLIT_IP4_ADDR(laddr),
		 ntohs(lport),
		 SPLIT_IP4_ADDR(daddr),
		 ntohs(dport));


	if (!krgnode_online(owner))
		goto out;

	desc = rpc_begin(CLUSTER_DELETE_ESTABLISHED, owner);
	if (!desc)
		goto out;

	err = rpc_pack_type(desc, laddr);
	if (err)
		goto out_end;

	err = rpc_pack_type(desc, lport);
	if (err)
		goto out_end;

	err = rpc_pack_type(desc, daddr);
	if (err)
		goto out_end;

	err = rpc_pack_type(desc, dport);
	if (err)
		goto out_end;

	if (rpc_unpack_type_from(desc, owner, err))
		err = -EIO;

out_end:
	rpc_end(desc, 0);
out:
	return err;
}


int krgip_cluster_delete_established(__be32 laddr, __be16 lport, __be32 daddr, __be16 dport)
{
	kerrighed_node_t owner;
	objid_t objid;
	struct krg_namespace *krg_ns;
	struct netns_krgip *krgip;
	struct kddm_set *established_set, *port_set;
	struct krgip_cluster_port_kddm_object *port_obj;
	struct krgip_cluster_established_kddm_object *established_obj;
	int err = -EIO;

	pr_debug("local request for this established entry to be deleted :\n"
		"%u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
		 SPLIT_IP4_ADDR(laddr),
		 ntohs(lport),
		 SPLIT_IP4_ADDR(daddr),
		 ntohs(dport));


	krg_ns = find_get_krg_ns();
	if (!krg_ns)
		goto out;

	krgip = &krg_ns->root_nsproxy.net_ns->krgip;
	if (!krgip)
		goto out_ns;

	port_set = krgip->cluster_ports_tcp;
	established_set = krgip->cluster_established_tcp;
	if (!port_set || !established_set)
		goto out_ns;

	/* The port obj is our mutex. If we've got it, the established obj can't change
	 * its owner. */
	port_obj = _kddm_get_object(port_set, htons(lport));
	if (!port_obj)
		goto out_ns;

	/* First get the object to check the owner */
	objid = (laddr << 16) + lport;
	established_obj = _kddm_get_object(established_set, objid);
	if (!established_obj)
		goto out_port;
	owner = established_obj->owner;
	_kddm_put_object(established_set, objid);

	if (owner == kerrighed_node_id || owner == KERRIGHED_NODE_ID_NONE) {
		err = krgip_cluster_do_delete_established(established_set,
							  laddr, lport, daddr, dport);
		goto out_port;
	}

	/* We are not the owner, lets do a rpc call */
	err = krgip_cluster_rpc_delete_established(owner, laddr, lport, daddr, dport);

out_port:
	_kddm_put_object(port_set, htons(lport));
out_ns:
	put_krg_ns(krg_ns);
out:
	return err;
}
EXPORT_SYMBOL(krgip_cluster_delete_established);

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

static struct krgip_addrport *krgip_addrport_alloc(__be32 daddr, __be16 dport)
{
	struct krgip_addrport *addrport;

	addrport = kmalloc(sizeof(*addrport), GFP_KERNEL);
	if (addrport) {
		addrport->daddr = daddr;
		addrport->dport = dport;
	}
	return addrport;
}

static void krgip_addrport_free(struct krgip_addrport *addrport)
{
	kfree(addrport);
}

static int krgip_cluster_established_alloc_object(struct kddm_obj *obj_entry,
						  struct kddm_set *set,
						  objid_t objid)
{
	struct krgip_cluster_established_kddm_object *obj;
	struct krg_namespace *krg_ns;
	struct krgip_local_ports *ports;

	obj = kmalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return -ENOMEM;

	INIT_LIST_HEAD(&obj->established);
	obj->laddr = (objid & 0x0000ffffffff0000) >> 16;
	obj->lport = (objid & 0x000000000000ffff);
	obj->owner = 0;

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);
	ports = krgip_local_ports_find(&krg_ns->root_nsproxy.net_ns->krgip, obj->laddr);
	put_krg_ns(krg_ns);
	if (!ports) {
		kfree(obj);
		return -ENOMEM;
	}

	obj->established_resp = krgip_established_resp_alloc(obj->lport, obj);
	if (!obj->established_resp)
		return -ENOMEM;

	obj->established_resp->responsible = 0;
	krgip_established_resp_add(ports, obj->established_resp);

	obj_entry->object = obj;
	return 0;
}

static int krgip_cluster_established_first_touch(struct kddm_obj *obj_entry,
						 struct kddm_set *set,
						 objid_t objid,
						 int flags)
{
	struct krgip_cluster_established_kddm_object *obj;
	int err;

	err = krgip_cluster_established_alloc_object(obj_entry, set, objid);
	if (!err) {
		obj = obj_entry->object;
	}

	return err;
}

static int krgip_cluster_established_remove_object(void *object,
						   struct kddm_set *set,
						   objid_t objid)
{
	struct krgip_cluster_established_kddm_object *obj = object;
	struct krgip_addrport *dest, *safe;

	list_for_each_entry_safe(dest, safe, &obj->established, list) {
		list_del(&dest->list);
		krgip_addrport_free(dest);
	}

	kfree(obj);

	return 0;
}

static int krgip_cluster_established_import_object(struct rpc_desc *desc,
						   struct kddm_set *set,
						   struct kddm_obj *obj_entry,
						   objid_t objid,
						   int flags)
{
	struct krgip_cluster_established_kddm_object *obj = obj_entry->object;
	LIST_HEAD(tmp);
	LIST_HEAD(to_free);
	__be32 daddr;
	__be16 dport;
	struct krgip_addrport *entry, *safe;
	int err;

	for (;;) {
		err = rpc_unpack_type(desc, daddr);
		if (err)
			goto out_free;
		err = rpc_unpack_type(desc, dport);
		if (err)
			goto out_free;

		/* The rpc packet ends by a zeroed data */
		if (!daddr || !dport)
			break;

		entry = krgip_addrport_alloc(daddr, dport);
		if (!entry) {
			err = -ENOMEM;
			goto out_free;
		}
		list_add(&entry->list, &tmp);
	}

	rpc_unpack_type(desc, obj->owner);
	if (err)
		obj->owner = KERRIGHED_NODE_ID_NONE;


	list_splice_init(&obj->established, &to_free);
	list_splice_init(&tmp, &obj->established);

	list_splice(&to_free, &tmp);
out_free:
	list_for_each_entry_safe(entry, safe, &tmp, list) {
		list_del(&entry->list);
		krgip_addrport_free(entry);
	}

	return err;
}

static int krgip_cluster_established_export_object(struct rpc_desc *desc,
						   struct kddm_set *set,
						   struct kddm_obj *obj_entry,
						   objid_t objid,
						   int flags)
{
	struct krgip_cluster_established_kddm_object *obj = obj_entry->object;
	struct krgip_addrport *entry;
	struct inet_ehash_bucket *ehash;
	const struct hlist_nulls_node *node;
	struct sock *sk;
	unsigned int i;
	__be32 zero4b = 0;
	__be16 zero2b = 0;
	int err;

	rcu_read_lock();

	/* Add our own established hash to the export */
	for (i=0; i<tcp_hashinfo.ehash_size; i++) {
		ehash = &tcp_hashinfo.ehash[i];

		sk_nulls_for_each_rcu(sk, node, &ehash->chain) {
			pr_debug("entry found in connections :\n"
				 "%u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
				 SPLIT_IP4_ADDR(inet_sk(sk)->saddr),
				 ntohs(inet_sk(sk)->sport),
				 SPLIT_IP4_ADDR(inet_sk(sk)->daddr),
				 ntohs(inet_sk(sk)->dport));

			/* [TODO] Add a check on the net_ns */
			if (inet_sk(sk)->saddr == obj->laddr
			    && inet_sk(sk)->sport == obj->lport) {
				entry = krgip_addrport_alloc(inet_sk(sk)->daddr,
							     inet_sk(sk)->dport);
				if (entry)
					list_add(&entry->list, &obj->established);
			}
		}

		sk_nulls_for_each_rcu(sk, node, &ehash->twchain) {
			pr_debug("Entry found in tw connections\n");

			if (inet_sk(sk)->daddr == obj->laddr
			    && inet_sk(sk)->dport == obj->lport) {
				entry = krgip_addrport_alloc(inet_sk(sk)->saddr,
							     inet_sk(sk)->sport);
				if (entry)
					list_add(&entry->list, &obj->established);
			}
		}

	}

	rcu_read_unlock();


	list_for_each_entry(entry, &obj->established, list) {
		err = rpc_pack_type(desc, entry->daddr);
		if (err)
			return err;
		err = rpc_pack_type(desc, entry->dport);
		if (err)
			return err;
	}

	rpc_pack_type(desc, zero4b);
	rpc_pack_type(desc, zero2b);

	rpc_pack_type(desc, obj->owner);

	return err;
}

void krgip_cluster_established_change_state(struct kddm_obj * obj_entry, struct kddm_set * set,
					    objid_t objid, kddm_obj_state_t state)
{
	struct krgip_cluster_established_kddm_object *obj = obj_entry->object;

	if (!obj)
		return;

	if (state == INV_COPY) {
		pr_debug("loosing ownership of established %u\n", (unsigned int) objid);

		obj->established_resp->responsible = 0;
	}

	if (state == WRITE_OWNER) {
		pr_debug("becoming owner of established %u\n", (unsigned int) objid);

		obj->established_resp->responsible = 1;
		obj->owner = kerrighed_node_id;
	}
}

static struct iolinker_struct krgip_cluster_established_io_linker = {
	.first_touch = krgip_cluster_established_first_touch,
	.alloc_object = krgip_cluster_established_alloc_object,
	.remove_object = krgip_cluster_established_remove_object,
	.export_object = krgip_cluster_established_export_object,
	.import_object = krgip_cluster_established_import_object,
	.change_state = krgip_cluster_established_change_state,
	.linker_name = "cluster_estbshd",
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

#if 0
int
krgip_cluster_ip_tcp_get_established_prepare(struct sock *sk,
					     unsigned short snum,
					     struct krgip_cluster_ip_kddm_object **ip_obj_p,
					     struct krgip_addr **addr,
					     struct krgip_established **established)
{
	struct inet_sock *inet = inet_sk(sk);
	struct netns_krgip *krgip = &sock_net(sk)->krgip;
	struct kddm_set *ip_set = krgip->cluster_ips;
	struct krgip_cluster_ip_kddm_object *ip_obj = NULL;
	int err;

	if (!ip_set || sk->sk_family != AF_INET || sk->sk_protocol != IPPROTO_TCP)
		return 0;

	if (inet->saddr == 0)
		return 0;

	ip_obj = _kddm_get_object(ip_set, inet->saddr);
	if (IS_ERR(ip_obj))
		return PTR_ERR(ip_obj);
	BUG_ON(!ip_obj);

	snum = htons(snum);
	port_obj = _kddm_grab_object(port_set, snum);
	if (IS_ERR(port_obj)) {
		err = PTR_ERR(port_obj);
		goto err_put;
	}
	BUG_ON(!port_obj);

	err = -EADDRINUSE;

	if (ip_obj->nr_nodes && krgip_established_find(ip_obj->krgip_local_ports->established_tcp,
						       inet->daddr, inet->dport) {
		goto err_put;
	}

	err = -ENOMEM;
	*established = krgip_established_alloc(inet->saddr, snum);
	if (!*established)
		goto err_put;

	*addr = krgip_addr_alloc(bindaddr);
	if (!*addr) {
		krgip_established_free(*established);
		*established = NULL;
		goto err_put;
	}

	*ip_obj_p = ip_obj;

	return 0;

err_put:
	krgip_cluster_ip_put_or_remove(ip_set, ip_obj);

	return err;
}

void
krgip_cluster_ip_tcp_get_established_finish(struct sock *sk,
					    struct krgip_cluster_ip_kddm_object *ip_obj,
					    struct krgip_addr *addr,
					    struct krgip_established **established,
					    int error)
{
	struct netns_krgip *krgip = &sock_net(sk)->krgip;
	struct kddm_set *ip_set = krgip->cluster_ips;

	if (!ip_obj)
		return;

	if (error) {
		krgip_cluster_ip_put_or_remove(ip_set, ip_obj);
		krgip_established_free(port);
		krgip_addr_free(addr);
		return;
	}

	inet_sk(sk)->is_krgip = 1;

	krgip_established_add(ip_obj->local_ports, established);

	_kddm_put_object(ip_set, ip_obj->addr);
}
#endif

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
/*	if (sk->sk_userlocks & SOCK_BINDADDR_LOCK) {*/
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
#if 0
	struct kddm_set *established_set = krgip->cluster_established_tcp;
	struct krgip_cluster_established_kddm_object *established_obj;
	objid_t objid;
	struct krgip_established_resp *established_resp;
	struct krgip_local_ports *ports;
	int i;
#endif

	if (!port_obj)
		return;
#if 0
	if (established_set) {
		/* Become owner of established objs */
		if (ip_obj) {
			objid = (ip_obj->addr << 16) + port_obj->num;
			established_obj = _kddm_grab_object(established_set, objid);
			established_obj->owner = KERRIGHED_NODE_ID_NONE;
			ports = krgip_local_ports_find(krgip, ip_obj->addr);
			krgip_established_tcp_resp_del(ports, port_obj->num);
			_kddm_put_object(established_set, objid);

			pr_debug("release established %u\n", (unsigned int) objid);
		} else {
			/* I'd really like something better... */
			for (i = 0; i < KRGIP_LOCAL_PORTS_IP_TABLE_SIZE; i++) {
				list_for_each_entry(ports, &krgip->local_ports_ip_table[i], list) {
					objid = (ports->addr << 16) + port_obj->num;
					established_obj = _kddm_grab_object(established_set, objid);
					_kddm_put_object(established_set, objid);

					pr_debug("release established %u\n", (unsigned int) objid);
				}
			}
		}
	}
#endif

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
		krgip->cluster_established_tcp = NULL;
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

	set = create_new_kddm_set(kddm_def_ns, CLUSTER_ESTABLISHED_TCP_KDDM_ID,
				  CLUSTER_ESTABLISHED_LINKER,
				  KDDM_RR_DEF_OWNER,
				  0,
				  KDDM_LOCAL_EXCLUSIVE);
	if (IS_ERR(set))
		goto err_established_tcp;
	krgip->cluster_established_tcp = set;

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
err_established_tcp:
	_destroy_kddm_set(krgip->cluster_established_tcp);
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

		_destroy_kddm_set(krgip->cluster_established_tcp);
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
	register_io_linker(CLUSTER_ESTABLISHED_LINKER, &krgip_cluster_established_io_linker);

	err = rpc_register_int(CLUSTER_IP_UNUSED, handle_cluster_ip_unused, 0);
	if (err)
		panic("Kerrighed: Could not register RPC handler CLUSTER_IP_UNUSED!\n");

	err = rpc_register_int(CLUSTER_DELETE_ESTABLISHED, handle_cluster_delete_established, 0);
	if (err)
		panic("Kerrighed: Could not register RPC handler CLUSTER_IP_UNUSED!\n");

	err = register_pernet_subsys(&krgip_cluster_ip_subsys);
	if (err)
		panic("Kerrighed: Could not register cluster_ip subsys!\n");

	return err;
}
