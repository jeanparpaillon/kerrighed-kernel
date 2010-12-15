/*
 *  kerrighed/net/krg_clusterip_handlers.c
 *
 *  Copyright (C) 2010, Louis Rilling - Kerlabs
 *  Copyright (C) 2010, Emmanuel Thierry - Kerlabs
 */

#include <linux/socket.h>
#include <linux/in.h>
/*#include <linux/slab.h>*/
/*#include <linux/hash.h>*/
/*#include <linux/mutex.h>*/
/*#include <linux/spinlock.h>*/
#include <linux/err.h>
#include <linux/module.h>
/*#include <net/sock.h>*/
#include <net/tcp.h>
/*#include <net/inet_sock.h>*/
#include <net/net_namespace.h>
#include <net/krgrpc/rpc.h>
#include <kerrighed/krgnodemask.h>
#include <kerrighed/namespace.h>
#include <kerrighed/hotplug.h>
#include <kerrighed/krg_clusterip.h>
#include <kddm/kddm.h>



/************** Ip unused handlers ***************/

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
	struct krg_namespace *krg_ns;
	struct rpc_desc *desc;
	krgnodemask_t nodes;
	kerrighed_node_t node;
	int err = 0;

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);

	membership_online_hold();
	if (!krgnode_online(kerrighed_node_id))
		goto out;

	err = -ENOMEM;
	krgnodes_copy(nodes, krgnode_online_map);
	desc = rpc_begin_m(CLUSTER_IP_UNUSED, krg_ns->rpc_comm, &nodes);
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
	put_krg_ns(krg_ns);

	return err;
}
EXPORT_SYMBOL(krgip_cluster_ip_unused);



/********** Add/Del established handlers *********/

static
int krgip_cluster_do_delete_established(struct kddm_set *established_set,
					__be32 laddr, __be16 lport, __be32 daddr, __be16 dport)
{
	objid_t objid;
	struct krgip_cluster_established_kddm_object *established_obj;
	struct krgip_addrport *todel;
	int err = -EIO;


	objid = ((long unsigned int) laddr << 16) + lport;
	established_obj = _kddm_grab_object(established_set, objid);
	if (!established_obj)
		goto out;

	todel = krgip_addrport_find(&established_obj->established, daddr, dport);
	if (todel) {
		err = 0;
		list_del(&todel->list);

		pr_debug("established entry deleted locally :\n"
			 "    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
			 SPLIT_IP4_ADDR(laddr),
			 ntohs(lport),
			 SPLIT_IP4_ADDR(daddr),
			 ntohs(dport));
	}

	_kddm_put_object(established_set, objid);

out:
	if (err)
		pr_debug("established entry deletion caused an error\n");

	return err;
}

static
int krgip_cluster_do_add_established(struct kddm_set *established_set,
					__be32 laddr, __be16 lport, __be32 daddr, __be16 dport)
{
	objid_t objid;
	struct krgip_cluster_established_kddm_object *established_obj;
	struct krgip_addrport *addrport, *toadd;
	int err = -EIO;


	objid = ((long unsigned int) laddr << 16) + lport;
	established_obj = _kddm_grab_object(established_set, objid);
	if (!established_obj)
		goto out;

	addrport = krgip_addrport_find(&established_obj->established, daddr, dport);
	if (addrport) {
		err = -EADDRINUSE;
		goto out_release;
	}

	toadd = krgip_addrport_alloc(daddr, dport);
	if (!toadd) {
		err = -ENOMEM;
		goto out_release;
	}

	err = 0;
	list_add(&toadd->list, &established_obj->established);

	pr_debug("established entry added locally :\n"
		 "    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
		 SPLIT_IP4_ADDR(laddr),
		 ntohs(lport),
		 SPLIT_IP4_ADDR(daddr),
		 ntohs(dport));

out_release:
	_kddm_put_object(established_set, objid);
out:
	if (err)
		pr_debug("established entry addition caused an error\n");

	return err;
}

static
void handle_cluster_addordel_established(struct rpc_desc *desc)
{
	__be32 laddr = 0;
	__be16 lport = 0;
	__be32 daddr = 0;
	__be16 dport = 0;
	int is_add = -1;
	struct krg_namespace *krg_ns;
	struct netns_krgip *krgip;
	struct kddm_set *established_set;
	int err = -EIO;


	err = rpc_unpack_type(desc, is_add);
	if (!err && is_add != 0 && is_add != 1)
		err = -EINVAL;
	if (err)
		goto out_cancel;

	err = rpc_unpack_type(desc, laddr);
	if (err)
		goto out_cancel;

	err = rpc_unpack_type(desc, lport);
	if (err)
		goto out_cancel;

	err = rpc_unpack_type(desc, daddr);
	if (err)
		goto out_cancel;

	err = rpc_unpack_type(desc, dport);
	if (err)
		goto out_cancel;

	pr_debug("rpc request for this established entry to be %s :\n"
		 "    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
		 is_add ? "added" : "deleted",
		 SPLIT_IP4_ADDR(laddr),
		 ntohs(lport),
		 SPLIT_IP4_ADDR(daddr),
		 ntohs(dport));


	err = -EIO;
	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);

	krgip = &krg_ns->root_nsproxy.net_ns->krgip;
	if (krgip) {
		established_set = krgip->cluster_established_tcp;
		if (established_set)
			err = (is_add ?
			      krgip_cluster_do_add_established(established_set,
							       laddr, lport, daddr, dport) :
			      krgip_cluster_do_delete_established(established_set,
								  laddr, lport, daddr, dport));
	}

	put_krg_ns(krg_ns);

	rpc_pack_type(desc, err);

	return;

out_cancel:
	rpc_cancel(desc);
	pr_debug("bad rpc request for an established entry deletion\n");
}

static
int krgip_cluster_rpc_addordel_established(kerrighed_node_t owner, int is_add,
					   __be32 laddr, __be16 lport,
					   __be32 daddr, __be16 dport)
{
	struct krg_namespace *krg_ns;
	struct rpc_desc *desc;
	int err = -EIO;

	BUG_ON(owner == KERRIGHED_NODE_ID_NONE);

	pr_debug("ask to node %u to %s established entry :\n"
		 "    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
		 owner,
		 is_add ? "add" : "del",
		 SPLIT_IP4_ADDR(laddr),
		 ntohs(lport),
		 SPLIT_IP4_ADDR(daddr),
		 ntohs(dport));

	krg_ns = find_get_krg_ns();
	BUG_ON(!krg_ns);

	if (!krgnode_online(owner))
		goto out;

	desc = rpc_begin(CLUSTER_ADDORDEL_ESTABLISHED, krg_ns->rpc_comm, owner);
	if (!desc)
		goto out;

	err = rpc_pack_type(desc, is_add);
	if (err)
		goto out_cancel;

	err = rpc_pack_type(desc, laddr);
	if (err)
		goto out_cancel;

	err = rpc_pack_type(desc, lport);
	if (err)
		goto out_cancel;

	err = rpc_pack_type(desc, daddr);
	if (err)
		goto out_cancel;

	err = rpc_pack_type(desc, dport);
	if (err)
		goto out_cancel;

	if (rpc_unpack_type(desc, err))
		err = -EIO;

	rpc_end(desc, 0);

out:
	if (err)
		pr_debug("rpc request caused an error\n");
	put_krg_ns(krg_ns);

	return err;

out_cancel:
	rpc_cancel(desc);
	goto out;
}

int krgip_cluster_addordel_established(int is_add,
				       __be32 laddr, __be16 lport,
				       __be32 daddr, __be16 dport)
{
	kerrighed_node_t owner;
	objid_t objid;
	struct krg_namespace *krg_ns;
	struct netns_krgip *krgip;
	struct kddm_set *established_set, *port_set;
	struct krgip_cluster_port_kddm_object *port_obj;
	struct krgip_cluster_established_kddm_object *established_obj;
	int err = -EIO;


	pr_debug("local request for this established entry to be %s :\n"
		 "    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
		 is_add ? "added" : "deleted",
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

	pr_debug("request made for a kerrighed ip\n");

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
	objid = ((long unsigned int) laddr << 16) + lport;
	established_obj = _kddm_get_object(established_set, objid);
	if (!established_obj)
		goto out_port;
	owner = established_obj->owner;
	_kddm_put_object(established_set, objid);

	if (owner == kerrighed_node_id || owner == KERRIGHED_NODE_ID_NONE) {
		err = (is_add ?
		       krgip_cluster_do_add_established(established_set,
							laddr, lport, daddr, dport) :
		       krgip_cluster_do_delete_established(established_set,
							   laddr, lport, daddr, dport));
		goto out_port;
	}

	/* We are not the owner, lets do a rpc call */
	err = krgip_cluster_rpc_addordel_established(owner, is_add, laddr, lport, daddr, dport);

out_port:
	_kddm_put_object(port_set, htons(lport));
out_ns:
	put_krg_ns(krg_ns);
out:
	return err;
}
EXPORT_SYMBOL(krgip_cluster_addordel_established);



/**************** Ip kddm handlers ***************/

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


void krgip_cluster_ip_put_or_remove(struct kddm_set *set,
				    struct krgip_cluster_ip_kddm_object *obj)
{
	if (obj->nr_nodes)
		_kddm_put_object(set, obj->addr);
	else
		_kddm_remove_frozen_object(set, obj->addr);
}


static struct iolinker_struct krgip_cluster_ip_io_linker = {
	.first_touch = krgip_cluster_ip_first_touch,
	.alloc_object = krgip_cluster_ip_alloc_object,
	.remove_object = krgip_cluster_ip_remove_object,
	.export_object = krgip_cluster_ip_export_object,
	.import_object = krgip_cluster_ip_import_object,
	.linker_name = "cluster_ip",
};



/*************** Port kddm handlers **************/

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

static struct iolinker_struct krgip_cluster_port_io_linker = {
	.first_touch = krgip_cluster_port_first_touch,
	.alloc_object = krgip_cluster_port_alloc_object,
	.remove_object = krgip_cluster_port_remove_object,
	.export_object = krgip_cluster_port_export_object,
	.import_object = krgip_cluster_port_import_object,
	.linker_name = "cluster_port",
};


/*********** Established kddm handlers ***********/

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
	obj->owner = KERRIGHED_NODE_ID_NONE;

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

	pr_debug("imported connections :\n");

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
		pr_debug("    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
			 SPLIT_IP4_ADDR((unsigned int) ((objid & 0x0000ffffffff0000) >> 16)),
			 ntohs(objid & 0x000000000000ffff),
			 SPLIT_IP4_ADDR(daddr),
			 ntohs(dport));
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

	pr_debug("listing established connections :\n");

	/* Add our own established hash to the export */
	for (i=0; i<tcp_hashinfo.ehash_size; i++) {
		ehash = &tcp_hashinfo.ehash[i];

		sk_nulls_for_each_rcu(sk, node, &ehash->chain) {
			pr_debug("    %u.%u.%u.%u:%u <=> %u.%u.%u.%u:%u\n",
				 SPLIT_IP4_ADDR(inet_sk(sk)->saddr),
				 ntohs(inet_sk(sk)->sport),
				 SPLIT_IP4_ADDR(inet_sk(sk)->daddr),
				 ntohs(inet_sk(sk)->dport));

			/* [TODO] Add a check on the net_ns */
			if (inet_sk(sk)->saddr == obj->laddr
			    && inet_sk(sk)->sport == obj->lport
			    && !krgip_addrport_find(&obj->established, inet_sk(sk)->daddr, inet_sk(sk)->dport)) {
				entry = krgip_addrport_alloc(inet_sk(sk)->daddr, inet_sk(sk)->dport);
				if (entry)
					list_add(&entry->list, &obj->established);
			}
		}
/*
		sk_nulls_for_each_rcu(sk, node, &ehash->twchain) {
			pr_debug("Entry found in tw connections\n");

			if (inet_sk(sk)->daddr == obj->laddr
			    && inet_sk(sk)->dport == obj->lport
			    && !krgip_addrport_find(&obj->established, inet_sk(sk)->daddr, inet_sk(sk)->dport)) {
				entry = krgip_addrport_alloc(inet_sk(sk)->saddr, inet_sk(sk)->sport);
				if (entry)
					list_add(&entry->list, &obj->established);
			}
		}
*/
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


/************** Registering handlers *************/

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

	err = rpc_register(CLUSTER_ADDORDEL_ESTABLISHED, handle_cluster_addordel_established, 0);
	if (err)
		panic("Kerrighed: Could not register RPC handler CLUSTER_ADDORDEL_ESTABLISHED!\n");

	err = register_pernet_subsys(&krgip_cluster_ip_subsys);
	if (err)
		panic("Kerrighed: Could not register cluster_ip subsys!\n");

	return err;
}
