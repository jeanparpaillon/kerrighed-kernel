#ifndef __KRG_CLUSTERIP_H__
#define __KRG_CLUSTERIP_H__

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/types.h>

#define SPLIT_IP4_ADDR(__addr_tosplit) ((__addr_tosplit) & 0x000000ff), ((__addr_tosplit) & 0x0000ff00) >> 8, ((__addr_tosplit) & 0x00ff0000) >> 16, ((__addr_tosplit) & 0xff000000) >> 24


struct kddm_set;

struct krgip_local_port {
	struct list_head list;
	__be16 port;
	struct rcu_head rcu;
};

struct krgip_local_ports {
	spinlock_t lock;
	struct list_head udp;
	struct list_head tcp;
	struct list_head established_tcp_resp;
	struct list_head list;
	__be32 addr;
	struct rcu_head rcu;
};

struct krgip_cluster_ip_kddm_object {
	struct krgip_local_ports *local_ports;
	int nr_nodes;
	__be32 addr;
};

struct krgip_addr {
	struct list_head list;
	__be32 addr;
};

struct krgip_cluster_port_kddm_object {
	struct list_head ips;
	kerrighed_node_t node;
	__be16 num;
};

struct krgip_established_resp {
	struct list_head list;
	__be16 lport;
	int responsible;
	struct krgip_cluster_established_kddm_object *kddm_obj;
	struct rcu_head rcu;
};

struct krgip_addrport {
	struct list_head list;
	__be32 daddr;
	__be16 dport;
};

struct krgip_cluster_established_kddm_object {
	struct list_head established;
	__be32 laddr;
	__be16 lport;
	kerrighed_node_t owner;
	struct krgip_established_resp *established_resp;
};

struct netns_krgip {
	struct kddm_set *cluster_ips;
	struct kddm_set *cluster_ports_udp;
	struct kddm_set *cluster_ports_tcp;
	struct kddm_set *cluster_established_tcp;
	struct list_head *local_ports_ip_table;
	struct krgip_local_ports local_ports_any;
};

struct krgip_local_port *krgip_local_port_alloc(__be16 num);
void krgip_local_port_free(struct krgip_local_port *port);

void krgip_local_ports_add(struct krgip_local_ports *ports,
			   struct krgip_local_port *port,
			   struct list_head *head);
void krgip_local_ports_del(struct krgip_local_ports *ports,
			   __be16 snum,
			   struct list_head *head);


struct krgip_established_resp *krgip_established_resp_alloc(__be16 lport,
							    struct krgip_cluster_established_kddm_object *kddm_obj);
void krgip_established_resp_free(struct krgip_established_resp *established);

void krgip_established_resp_add(struct krgip_local_ports *ports,
				struct krgip_established_resp *new_established);
void krgip_established_resp_del(struct krgip_local_ports *ports, __be16 lport);


static inline void krgip_local_ports_udp_add(struct krgip_local_ports *ports,
					     struct krgip_local_port *port)
{
	krgip_local_ports_add(ports, port, &ports->udp);
}

static inline void krgip_local_ports_udp_del(struct krgip_local_ports *ports,
					     __be16 snum)
{
	krgip_local_ports_del(ports, snum, &ports->udp);
}

static inline void krgip_local_ports_tcp_add(struct krgip_local_ports *ports,
					     struct krgip_local_port *port)
{
	krgip_local_ports_add(ports, port, &ports->tcp);
}

static inline void krgip_local_ports_tcp_del(struct krgip_local_ports *ports,
					     __be16 snum)
{
	krgip_local_ports_del(ports, snum, &ports->tcp);
}

static inline bool krgip_local_ports_empty(struct krgip_local_ports *ports)
{
	return list_empty(&ports->udp) && list_empty(&ports->tcp);
}

static
inline
struct krgip_local_port *krgip_local_port_find(struct list_head *head, __be16 port)
{
	struct krgip_local_port *pos;

	list_for_each_entry_rcu(pos, head, list)
		if (pos->port == port)
			return pos;
	return NULL;
}

int krgip_cluster_ip_unused(__be32 addr);

void krgip_cluster_ip_put_or_remove(struct kddm_set *set,
				    struct krgip_cluster_ip_kddm_object *obj);

struct krgip_addr *krgip_addr_alloc(__be32 addr);
void krgip_addr_free(struct krgip_addr *addr);

static
inline struct krgip_addr *krgip_addr_find(struct list_head *head, __be32 addr)
{
	struct krgip_addr *pos;

	list_for_each_entry(pos, head, list)
		if (pos->addr == addr)
			return pos;
	return NULL;
}

static
inline struct krgip_established_resp *krgip_responsible_find(struct list_head *head, __be16 lport)
{
	struct krgip_established_resp *pos;

	list_for_each_entry(pos, head, list)
		if (pos->lport == lport)
			return pos;
	return NULL;
}

static
inline struct krgip_addrport *krgip_addrport_find(struct list_head *head, __be32 daddr, __be16 dport)
{
	struct krgip_addrport *pos;

	pr_debug("testing against addresses :\n");
	list_for_each_entry(pos, head, list) {
		pr_debug("    %u.%u.%u.%u:%u\n",
			 SPLIT_IP4_ADDR(pos->daddr),
			 ntohs(pos->dport));

		if (pos->daddr == daddr && pos->dport == dport)
			return pos;
	}
	return NULL;
}

struct krgip_local_ports *krgip_local_ports_find(struct netns_krgip *krgip, __be32 addr);

void
krgip_cluster_port_put_or_remove(struct kddm_set *set,
				 struct krgip_cluster_port_kddm_object *obj);


int krgip_cluster_delete_established(__be32 laddr, __be16 lport, __be32 daddr, __be16 dport);

struct sock;

#if 0
void
krgip_cluster_ip_established_unhash_prepare(struct sock *sk,
					    struct krgip_cluster_established_kddm_object **established_obj_p,
					    struct krgip_cluster_port_kddm_object **port_obj_p);
void
krgip_cluster_ip_established_unhash_finish(struct sock *sk,
					   struct krgip_cluster_established_kddm_object *established_obj,
					   struct krgip_cluster_port_kddm_object *port_obj);

#endif



int
krgip_cluster_ip_tcp_get_port_prepare(struct sock *sk,
				      unsigned short snum,
				      struct krgip_cluster_ip_kddm_object **ip_obj_p,
				      struct krgip_cluster_port_kddm_object **port_obj_p,
				      struct krgip_addr **addr,
				      struct krgip_local_port **port);
void
krgip_cluster_ip_tcp_get_port_finish(struct sock *sk,
				     struct krgip_cluster_ip_kddm_object *ip_obj,
				     struct krgip_cluster_port_kddm_object *port_obj,
				     struct krgip_addr *addr,
				     struct krgip_local_port *port,
				     int error);
void
krgip_cluster_ip_tcp_unhash_prepare(struct sock *sk,
				    struct krgip_cluster_ip_kddm_object **ip_obj_p,
				    struct krgip_cluster_port_kddm_object **port_obj_p);
void
krgip_cluster_ip_tcp_unhash_finish(struct sock *sk,
				   struct krgip_cluster_ip_kddm_object *ip_obj,
				   struct krgip_cluster_port_kddm_object *port_obj);

int krgip_cluster_ip_start(void);

#endif /* __KRG_CLUSTERIP_H__ */
