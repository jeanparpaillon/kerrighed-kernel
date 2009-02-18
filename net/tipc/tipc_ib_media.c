/*
 * Copyright (c) 2008 Kerlabs.  All rights reserved.
 *
 * This code is partly based on the IPoIB management code (ipoib_ib.c).
 */

#include <rdma/rdma_cm.h>
#include <net/tipc/tipc.h>
#include <net/tipc/tipc_plugin_if.h>
#include <net/tipc/tipc_plugin_msg.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/inet.h>

#include <linux/kdb.h>
#include <linux/kdbprivate.h>

#include <kerrighed/krginit.h>

#define TIPC_IB_NUM_WC 4

#ifdef IB_GRH_BYTES
#error IB_GRH_BYTES already defined
#else
#define IB_GRH_BYTES 0
#endif

#define TIPC_IB_PACKET_SIZE (PAGE_SIZE+1024)
#define TIPC_IB_BUF_SIZE (TIPC_IB_PACKET_SIZE + IB_GRH_BYTES)

#define TIPC_IB_TX_RING_SIZE 64
#define TIPC_IB_RX_RING_SIZE 128

#define	TIPC_IB_OP_RECV	(1ul << 31)

#define	TIPC_IB_FLAG_OPER_UP      0
#define	TIPC_IB_FLAG_INITIALIZED  1
#define	TIPC_IB_FLAG_ADMIN_UP 	  2


MODULE_AUTHOR("Pascal Gallard");
MODULE_DESCRIPTION("IB TIPC media");
MODULE_LICENSE("GPL");

int tipc_ib_sendq_size __read_mostly = TIPC_IB_TX_RING_SIZE;
int tipc_ib_recvq_size __read_mostly = TIPC_IB_RX_RING_SIZE;

module_param_named(send_queue_size, tipc_ib_sendq_size, int, 0444);
MODULE_PARM_DESC(send_queue_size, "Number of descriptors in send queue");
module_param_named(recv_queue_size, tipc_ib_recvq_size, int, 0444);
MODULE_PARM_DESC(recv_queue_size, "Number of descriptors in receive queue");

#define LOG_MAX_SIZE (128*1024)

struct log {
	short op;
	short nodeid;
	unsigned int id;
	unsigned long p;
};

static DEFINE_PER_CPU(void*, log_buffer);
static DEFINE_PER_CPU(struct log*, log_index);

static
void log_init(void){
	int cpuid;
	for_each_online_cpu(cpuid){
		per_cpu(log_buffer, cpuid) = kzalloc(LOG_MAX_SIZE, GFP_KERNEL);
		per_cpu(log_index, cpuid) = per_cpu(log_buffer, cpuid);
		printk("log_buffer[%d] = %p\n", cpuid, per_cpu(log_buffer, cpuid));
		printk("&log_index[%d] = %p\n", cpuid, &per_cpu(log_index, cpuid));
	}
}

inline
void log_write(short op, short nodeid, unsigned int id, void *p){
	if (op==0 || nodeid==0){
		printk("log_write: op=%x nodeid=%d id=%x p=%p\n", op, nodeid, id, p);
		BUG();
	}
	if((void*)per_cpu(log_index, smp_processor_id())-(void*)per_cpu(log_buffer, smp_processor_id())>=LOG_MAX_SIZE)
		return;
	per_cpu(log_index, smp_processor_id())->op = op;
	per_cpu(log_index, smp_processor_id())->nodeid = nodeid;
	per_cpu(log_index, smp_processor_id())->id = id;
	per_cpu(log_index, smp_processor_id())->p = (u64)p;
	per_cpu(log_index, smp_processor_id())++;
}

struct tipc_ib_per_node {
	struct rdma_cm_id *cm_id;
	struct ib_cq *cq;

	struct tipc_ib_rx_buf *rx_ring;

	spinlock_t node_lock;
	struct tipc_ib_tx_buf *tx_ring;
	unsigned tx_head;
	unsigned tx_tail;

	struct sk_buff *rx_head;
	struct sk_buff *rx_tail;

	int tx_stopped;

	struct tipc_ib_device *tib_dev;
	struct tasklet_struct tasklet;

	kerrighed_node_t id;

	struct ib_wc wc[TIPC_IB_NUM_WC];

};

struct tipc_ib_device {
	struct ib_device *ib_dev;
	struct list_head list;

	struct ib_sge tx_sge;
	struct ib_send_wr tx_wr;

	unsigned long flags;

	spinlock_t lock;

	struct tipc_ib_per_node *nodes[KERRIGHED_MAX_NODES];

	struct ib_pd *pd;
	struct ib_mr *mr;

	struct sk_buff *tx_queue;
	struct sk_buff *tx_queue_tail;

	struct tipc_bearer *bearer;

	krgnodemask_t ongoing_connections;
	krgnodemask_t connected_nodes;
	krgnodemask_t detected_nodes;
};

struct tipc_ib_rx_buf {
	struct sk_buff *skb;
	u64		mapping;
};

struct tipc_ib_tx_buf {
	struct sk_buff *skb;
	u64		mapping;
};

struct tipc_ib_enable_work_data {
	struct work_struct work;
	struct tipc_bearer *tb_ptr;
};

static struct notifier_block tipc_ib_notifier;

static LIST_HEAD(tipc_ib_devices_list);



void __tipc_recv_msg(unsigned long __node){
	struct tipc_ib_per_node *node = (struct tipc_ib_per_node*)__node;
	unsigned long flags;
	struct sk_buff *list, *iter;

	spin_lock_irqsave(&node->node_lock, flags);
	list = node->rx_head;
	node->rx_head = node->rx_tail = NULL;
	spin_unlock_irqrestore(&node->node_lock, flags);

	while((iter = list)){
		list = iter->next;
		iter->next = iter->prev = NULL;
		tipc_recv_msg(iter, node->tib_dev->bearer);
	}
}

/**
   Check if an IB device is already registred

   ib_dev: the IB device

   return:
   If found we return the corresponding tipc_ib_device struct,
   Otherwhise we try to allocate and initialize a corresponding structure.

**/
inline
struct tipc_ib_device* tipc_ib_device_lookup(struct ib_device *ibdev, struct tipc_bearer *bearer){
	struct tipc_ib_device *tipc_ib_dev;
	int i;

	list_for_each_entry(tipc_ib_dev, &tipc_ib_devices_list, list){
		if(tipc_ib_dev->ib_dev == ibdev)
			return tipc_ib_dev;
	}

	tipc_ib_dev = kmalloc(sizeof(*tipc_ib_dev), GFP_ATOMIC);
	if(!tipc_ib_dev)
		return NULL;

	spin_lock_init(&tipc_ib_dev->lock);
	tipc_ib_dev->ib_dev = ibdev;

	for(i=0;i<KERRIGHED_MAX_NODES;i++)
		tipc_ib_dev->nodes[i] = NULL;

	tipc_ib_dev->tx_queue = tipc_ib_dev->tx_queue_tail = NULL;
	tipc_ib_dev->bearer = bearer;

	list_add(&tipc_ib_dev->list, &tipc_ib_devices_list);

	krgnodes_clear(tipc_ib_dev->ongoing_connections);
	krgnodes_clear(tipc_ib_dev->connected_nodes);
	krgnodes_clear(tipc_ib_dev->detected_nodes);

	return tipc_ib_dev;
}

inline
struct tipc_ib_per_node* tipc_ib_allocate_and_init_per_node(struct tipc_ib_device *tib_dev,
							    kerrighed_node_t nodeid){
	struct tipc_ib_per_node *ret;

	BUG_ON(!tib_dev);

	ret = kmalloc(sizeof(*ret), GFP_ATOMIC);
	if(!ret)
		return ret;

	spin_lock_init(&ret->node_lock);
	ret->tib_dev = tib_dev;

	ret->rx_ring = kzalloc(tipc_ib_recvq_size * sizeof *ret->rx_ring,
				GFP_ATOMIC);
	if (!ret->rx_ring) {
		printk(KERN_WARNING "%s: failed to allocate RX ring (%d entries)\n",
		       tib_dev->ib_dev->name, tipc_ib_recvq_size);
		goto out_ret_cleanup;
	}

	ret->tx_stopped = 1;
	ret->tx_head = ret->tx_tail = 0;

	ret->tx_ring = kzalloc(tipc_ib_sendq_size * sizeof *ret->tx_ring,
				GFP_ATOMIC);
	if (!ret->tx_ring) {
		printk(KERN_WARNING "%s: failed to allocate TX ring (%d entries)\n",
		       tib_dev->ib_dev->name, tipc_ib_sendq_size);
		goto out_rx_ring_cleanup;
	}

	tasklet_init(&ret->tasklet, __tipc_recv_msg, (unsigned long)ret);

	ret->rx_head = ret->rx_tail = NULL;

	ret->id = nodeid;

	return ret;

 out_rx_ring_cleanup:
	kfree(ret->rx_ring);
 out_ret_cleanup:
	kfree(ret);

	return NULL;
}

inline
void tipc_ib_free_per_node(struct tipc_ib_per_node *node){
	if(node->rx_head)
		printk("WARNING: RX queue not empty\n");

	if(node->tx_head)
		printk("WARNING: TX queue not empty\n");

	tasklet_disable(&node->tasklet);
	tasklet_kill(&node->tasklet);

	kfree(node->rx_ring);
	kfree(node->tx_ring);
	kfree(node);
}

static
int tipc_ib_post_receive(struct tipc_ib_per_node *node, int id){
	struct ib_sge list;
	struct ib_recv_wr param;
	struct ib_recv_wr *bad_wr;
	int ret;

	list.addr     = node->rx_ring[id].mapping;
	list.length   = TIPC_IB_BUF_SIZE;
	list.lkey     = node->tib_dev->mr->lkey;

	param.next    = NULL;
	param.wr_id   = id | TIPC_IB_OP_RECV;
	param.sg_list = &list;
	param.num_sge = 1;

	ret = ib_post_recv(node->cm_id->qp, &param, &bad_wr);
	if (unlikely(ret)) {
		ib_dma_unmap_single(node->tib_dev->ib_dev, node->rx_ring[id].mapping,
				    TIPC_IB_BUF_SIZE, DMA_FROM_DEVICE);
		log_write(2, node->id, id, node->rx_ring[id].skb);
		dev_kfree_skb_any(node->rx_ring[id].skb);
		node->rx_ring[id].skb = NULL;
	}

	return ret;
}

static
int tipc_ib_alloc_rx_skb(struct tipc_ib_per_node *node, int id){
	struct sk_buff *skb;
	u64 addr;

	skb = dev_alloc_skb(TIPC_IB_BUF_SIZE + 4);
	if (!skb)
		return -ENOMEM;

	/*
	 * IB will leave a 40 byte gap for a GRH and IPoIB adds a 4 byte
	 * header.  So we need 4 more bytes to get to 48 and align the
	 * IP header to a multiple of 16.
	 */
	skb_reserve(skb, 4);

	addr = ib_dma_map_single(node->tib_dev->ib_dev, skb->data, TIPC_IB_BUF_SIZE,
				 DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(node->tib_dev->ib_dev, addr))) {
		dev_kfree_skb_any(skb);
		return -EIO;
	}

	log_write(1, node->id, id, skb);
	node->rx_ring[id].skb     = skb;
	node->rx_ring[id].mapping = addr;

	return 0;
}

static
int tipc_ib_post_receives(struct tipc_ib_per_node *node){
	int i;

	for (i = 0; i < tipc_ib_recvq_size; ++i) {
		if (tipc_ib_alloc_rx_skb(node, i))
			return -ENOMEM;

		if (tipc_ib_post_receive(node, i))
			return -EIO;

	}

	return 0;
}

static
void tipc_ib_handle_rx_wc(struct tipc_ib_per_node *node, struct ib_wc *wc){
	unsigned int wr_id = wc->wr_id & ~TIPC_IB_OP_RECV;
	struct sk_buff *skb;
	u64 addr;

	log_write(0x02ff, node->id, wr_id, node);
	if (unlikely(wr_id >= tipc_ib_recvq_size))
		return;

	BUG_ON(!node);
	BUG_ON(!node->rx_ring[wr_id].skb);
	skb  = node->rx_ring[wr_id].skb;
	addr = node->rx_ring[wr_id].mapping;
	BUG_ON(!skb);

	log_write(0x03ff, node->id, wr_id, skb);
	if (unlikely(wc->status != IB_WC_SUCCESS)) {
		log_write(0x04ff, node->id, wr_id, skb);
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			printk("failed recv event (status=%d, wrid=%d vend_err %x)\n",
			       wc->status, wr_id, wc->vendor_err);

		log_write(0x05ff, node->id, wr_id, skb);
		if((u64)skb < 0x00ffffffffffffff){
			log_write(3, node->id, wr_id, node->rx_ring[wr_id].skb);
			printk("nodeid=%d id=%x %p\n", node->id, wr_id, node->rx_ring[wr_id].skb);
			node->rx_ring[wr_id].skb = NULL;
			BUG();
		}

		log_write(0x06ff, node->id, wr_id, node);
		log_write(0x07ff, node->id, wr_id, node->tib_dev);
		log_write(0x08ff, node->id, wr_id, node->tib_dev->ib_dev);
		//BUG_ON(!node);
		//BUG_ON(!node->tib_dev);
		//BUG_ON(!node->tib_dev->ib_dev);
		ib_dma_unmap_single(node->tib_dev->ib_dev, addr,
				    TIPC_IB_BUF_SIZE, DMA_FROM_DEVICE);
		log_write(4, node->id, wr_id, node->rx_ring[wr_id].skb);
		dev_kfree_skb_any(skb);
		node->rx_ring[wr_id].skb = NULL;
		return;
	}

	/*
	 * If we can't allocate a new RX buffer, dump
	 * this packet and reuse the old buffer.
	 */
	if (unlikely(tipc_ib_alloc_rx_skb(node, wr_id))) {
		goto repost;
	}

	ib_dma_unmap_single(node->tib_dev->ib_dev, addr, TIPC_IB_BUF_SIZE, DMA_FROM_DEVICE);

	skb_put(skb, wc->byte_len);
	skb_pull(skb, IB_GRH_BYTES);

	skb->next = NULL;
	spin_lock(&node->node_lock);
	if(node->rx_head){
		node->rx_tail->next = skb;
		node->rx_tail = skb;
	}else{
		node->rx_head = node->rx_tail = skb;
	}
	spin_unlock(&node->node_lock);

	tasklet_schedule(&node->tasklet);

repost:
	if (unlikely(tipc_ib_post_receive(node, wr_id)))
		printk("tipc_ib_post_receive failed "
			   "for buf %d\n", wr_id);
}

static
void tipc_ib_handle_tx_wc(struct tipc_ib_per_node *node, struct ib_wc *wc){
	unsigned int wr_id = wc->wr_id;
	struct tipc_ib_tx_buf *tx_req;
	unsigned long flags;

	if (unlikely(wr_id >= tipc_ib_sendq_size)) {
		return;
	}

	tx_req = &node->tx_ring[wr_id];

	ib_dma_unmap_single(node->tib_dev->ib_dev, tx_req->mapping,
			    tx_req->skb->len, DMA_TO_DEVICE);

	dev_kfree_skb_any(tx_req->skb);

	spin_lock_irqsave(&node->node_lock, flags);
	++node->tx_tail;

	if (test_bit(TIPC_IB_FLAG_ADMIN_UP, &node->tib_dev->flags) &&
	    node->tx_head - node->tx_tail <= tipc_ib_sendq_size >> 1)
		node->tx_stopped = 0;

	spin_unlock_irqrestore(&node->node_lock, flags);

	if (wc->status != IB_WC_SUCCESS &&
	    wc->status != IB_WC_WR_FLUSH_ERR)
		printk("failed send event "
		       "(status=%d, wrid=%d vend_err %x)\n",
		       wc->status, wr_id, wc->vendor_err);
}

static
void tipc_ib_handle_wc(struct tipc_ib_per_node *node, struct ib_wc *wc){
	log_write(0x01ff, node->id, wc->wr_id, NULL);
	if (wc->wr_id & TIPC_IB_OP_RECV)
		tipc_ib_handle_rx_wc(node, wc);
	else
		tipc_ib_handle_tx_wc(node, wc);
}

static
void tipc_ib_completion(struct ib_cq *cq, void *dev_ptr){
	struct tipc_ib_per_node *node = (struct tipc_ib_per_node *) dev_ptr;
	int n, i;

	//for(i=0;i<tipc_ib_recvq_size;i++){
	//	if(node->rx_ring[i].skb && (u64)node->rx_ring[i].skb<0x00ffffffffffffff){
	//		printk("nodeid=%d id=%d %p\n", node->id, i, node->rx_ring[i].skb);
	//		BUG();
	//	}
	//}

	BUG_ON(!cq);
	BUG_ON(!dev_ptr);
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	do {
		n = ib_poll_cq(cq, TIPC_IB_NUM_WC, node->wc);
		for (i = 0; i < n; ++i){
			tipc_ib_handle_wc(node, node->wc + i);
		}
	} while (n == TIPC_IB_NUM_WC);
}

static
void tipc_ib_srv_event_handler(struct ib_event *event, void *context){
	printk("srv_event_handler\n");
}

static
int tipc_ib_srv_cm_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event){

	switch(event->event){
	case RDMA_CM_EVENT_CONNECT_REQUEST:{
		struct tipc_ib_device *tib_dev = cm_id->context;
		kerrighed_node_t nodeid = *((kerrighed_node_t*)event->param.conn.private_data);
		struct tipc_ib_per_node *node;
		struct rdma_conn_param conn_param = { };
		struct ib_qp_init_attr qp_attr = { };
		int err;

		//printk("srv_cm_handler: connect request\n");
		if(tib_dev->nodes[nodeid]){
			printk("tipc_ib_enable_bearer: connection already set (%d)\n", nodeid);
			break;
		}

		if(krgnode_isset(nodeid, tib_dev->ongoing_connections)){
			printk("ongoing connections %d\n", nodeid);
			rdma_reject(cm_id, NULL, 0);
			if (kerrighed_node_id > nodeid){
				printk("SRV detected_nodes %d\n", nodeid);
				krgnode_set(nodeid, tib_dev->detected_nodes);
			}
			break;
		}

		node = tib_dev->nodes[nodeid] = tipc_ib_allocate_and_init_per_node(tib_dev, nodeid);

		if(!tib_dev->nodes[nodeid])
			break;

		node->cm_id = cm_id;
		cm_id->context = node;

		node->cq = ib_create_cq(cm_id->device, tipc_ib_completion, tipc_ib_srv_event_handler,
					node, tipc_ib_sendq_size + tipc_ib_recvq_size + 1);

		if(!node->cq){
			printk("SRV error in create cq\n");
			return 1;
		}

		if(ib_req_notify_cq(node->cq, IB_CQ_NEXT_COMP)){
			printk("SRV error in notify cq 1\n");
			return 1;
		}

		qp_attr.cap.max_send_wr	 = tipc_ib_sendq_size;
		qp_attr.cap.max_send_sge = 1;
		qp_attr.cap.max_recv_wr	 = tipc_ib_recvq_size;
		qp_attr.cap.max_recv_sge = 1;

		qp_attr.send_cq		 = node->cq;
		qp_attr.recv_cq		 = node->cq;

		qp_attr.qp_type		 = IB_QPT_RC;

		err = rdma_create_qp(cm_id, node->tib_dev->pd, &qp_attr);
		if (err){
			printk("SRV error in create qp\n");
			return 1;
		}

		err = tipc_ib_post_receives(node);
		if(err){
			printk("tipc_ib_srv_cm_handler: error in tipc_ib_post_receives %d\n", err);
			return 1;
		}

		conn_param.responder_resources = 1;
		conn_param.private_data	       = NULL;
		conn_param.private_data_len    = 0;

		err = rdma_accept(cm_id, &conn_param);
		if(err){
			printk("SRV error in accept\n");
			return 1;
		}

		break;
	}
	case RDMA_CM_EVENT_ESTABLISHED:{
		struct tipc_ib_per_node *node = cm_id->context;

		node->tx_stopped = 0;
		krgnode_set(node->id, node->tib_dev->connected_nodes);
		//printk("SRV established to %d\n", node->id);
		break;

	}
	case RDMA_CM_EVENT_DISCONNECTED:
		printk("srv_cm_handler: disconnected\n");
		break;
	default:
		printk("srv_cm_handler: unkown case %d\n", event->event);
	}

	return 0;
}

static
void tipc_ib_clt_event_handler(struct ib_event *event, void *context){
	printk("clt_event_handler\n");
}

static
int tipc_ib_clt_cm_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event){
	struct tipc_ib_per_node *node = cm_id->context;
	int err;

	switch(event->event){
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		err = rdma_resolve_route(node->cm_id, 5000);
		if(err){
			printk("CLT rdma_resolve_route: error (%d)\n", err);
			return 1;
		}
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:{
		struct rdma_conn_param conn_param = { };
		struct ib_qp_init_attr qp_attr = { };

		node->cq = ib_create_cq(cm_id->device, tipc_ib_completion, tipc_ib_clt_event_handler,
				  node, tipc_ib_sendq_size + tipc_ib_recvq_size + 1);
		if(!node->cq){
			printk("CLT error in create cq\n");
			return 1;
		}

		if(ib_req_notify_cq(node->cq, IB_CQ_NEXT_COMP)){
			printk("CLT error in notify cq 1\n");
			return 1;
		}

		qp_attr.cap.max_send_wr	 = tipc_ib_sendq_size;
		qp_attr.cap.max_send_sge = 1;
		qp_attr.cap.max_recv_wr	 = tipc_ib_recvq_size;
		qp_attr.cap.max_recv_sge = 1;

		qp_attr.send_cq		 = node->cq;
		qp_attr.recv_cq		 = node->cq;

		qp_attr.qp_type		 = IB_QPT_RC;

		err = rdma_create_qp(cm_id, node->tib_dev->pd, &qp_attr);
		if (err){
			printk("CLT error in create qp\n");
			goto route_resolved_err;
		}

		err = tipc_ib_post_receives(node);
		if(err){
			printk("tipc_ib_clt_cm_handler: error in tipc_ib_post_receives %d\n", err);
			goto route_resolved_err;
			return 1;
		}

		conn_param.initiator_depth = 1;
		conn_param.retry_count	   = 7;
		conn_param.private_data = &kerrighed_node_id;
		conn_param.private_data_len = sizeof(kerrighed_node_id);

		err = rdma_connect(cm_id, &conn_param);
		if (err){
			printk("tipc_ib_clt_cm_handler: error in connect\n");
			goto route_resolved_err;
		}

		return 0;

route_resolved_err:
		rdma_destroy_qp(cm_id);
		ib_destroy_cq(node->cq);
		return err;

		break;
	}
	case RDMA_CM_EVENT_ESTABLISHED:{
		node->tx_stopped = 0;
		krgnode_set(node->id, node->tib_dev->connected_nodes);
		krgnode_clear(node->id, node->tib_dev->ongoing_connections);
		//printk("CLT established to %d\n", node->id);
		break;
	}

	case RDMA_CM_EVENT_REJECTED:
		rdma_destroy_qp(cm_id);
		ib_destroy_cq(node->cq);

 	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		//printk("CLT cm_handler: (%d) cx to %d discarded\n", event->event, node->id);
		node->tib_dev->nodes[node->id] = NULL;
		tipc_ib_free_per_node(node);
		krgnode_clear(node->id, node->tib_dev->ongoing_connections);
		break;
	default:
		printk("clt_cm_handler: unkown case %d (%d)\n", event->event, node->id);
		return 0;
	}

	return 0;
}

inline
int tipc_ib_send_ll(struct tipc_ib_per_node *node, unsigned int wr_id, u64 addr, int len){
	struct ib_sge sge;
	struct ib_send_wr send_wr = {};
	struct ib_send_wr *bad_send_wr;

	memset(&sge, 0, sizeof(sge));
	memset(&send_wr, 0, sizeof(send_wr));
	sge.addr   = addr;
	sge.length = len;
	sge.lkey   = node->tib_dev->mr->lkey;

	send_wr.wr_id		    = wr_id;
	send_wr.opcode		    = IB_WR_SEND;
	send_wr.send_flags	    = IB_SEND_SIGNALED;
	send_wr.sg_list		    = &sge;
	send_wr.num_sge		    = 1;

	return ib_post_send(node->cm_id->qp, &send_wr, &bad_send_wr);
}

inline
int tipc_ib_send(struct tipc_ib_per_node *node, struct sk_buff *skb){
	struct tipc_ib_tx_buf *tx_req;
	u64 addr;

	tx_req = &node->tx_ring[node->tx_head & (tipc_ib_sendq_size - 1)];
	tx_req->skb = skb;

	addr = ib_dma_map_single(node->tib_dev->ib_dev, skb->data, skb->len,
				 DMA_TO_DEVICE);
	if (unlikely(ib_dma_mapping_error(node->tib_dev->ib_dev, addr))) {
		dev_kfree_skb_any(skb);
		return 1;
	}
	tx_req->mapping = addr;

	if (unlikely(tipc_ib_send_ll(node, node->tx_head & (tipc_ib_sendq_size - 1),
				     addr, skb->len))) {
		ib_dma_unmap_single(node->tib_dev->ib_dev, addr, skb->len, DMA_TO_DEVICE);
		dev_kfree_skb_any(skb);
	} else {
		++node->tx_head;

		if (node->tx_head - node->tx_tail == tipc_ib_sendq_size) {
			printk("TX ring full, stopping kernel net queue %d - %d == %d\n",
			       node->tx_head, node->tx_tail, tipc_ib_sendq_size);
			node->tx_stopped = 1;
			BUG();
		}
	}

	return 0;
}

/**
 * tipc_ib_media_addr_init - initialize kerrighed-aware IB media address structure
 *
 * Structure's "value" field stores address info in the following format:
 * - Kerrighed node id [2 bytes (sizeof(short))]
 * - unused [18 bytes of zeroes]
 *
 */

static
void tipc_ib_media_addr_init(struct tipc_media_addr *a, kerrighed_node_t node){
	memset(a->value, 0, sizeof(a->value));
	*((short*)a->value) = node;

	a->media_id = TIPC_MEDIA_ID_IB;
        a->broadcast = 0;
}

/**
 * send_msg - send a TIPC message out over an IB interface
 */

static
int tipc_ib_send_msg(struct sk_buff *buf, struct tipc_bearer *tb_ptr,
		     struct tipc_media_addr *dest){
	struct tipc_ib_device *tib_dev = tb_ptr->usr_handle;
	struct sk_buff *buf_clone;
	unsigned long flags;

	if(test_bit(TIPC_IB_FLAG_ADMIN_UP, &tib_dev->flags)){
		if(dest->broadcast){
			kerrighed_node_t n;

			local_irq_save(flags);

			for_each_krgnode_mask(n, tib_dev->connected_nodes){
					if(tib_dev->nodes[n]->tx_stopped){
						printk("tipc_ib_send_msg: full ring\n");
					}else{
						buf_clone = skb_clone(buf, GFP_ATOMIC);
						if(unlikely(buf_clone == NULL))
							goto exit;
						else
							tipc_ib_send(tib_dev->nodes[n], buf_clone);
					}

				}

			local_irq_restore(flags);

		}else{
			buf_clone = skb_clone(buf, GFP_ATOMIC);
			if(buf_clone == NULL)
				goto exit;

			local_irq_save(flags);
			tipc_ib_send(tib_dev->nodes[*((kerrighed_node_t*)dest->value)], buf_clone);
			local_irq_restore(flags);
		}
	}else{
		printk("tipc_ib_send_msg: IB interface not available\n");
/*		if(tib_dev->tx_queue_tail){
			buf->next = NULL;
			buf->prev = tib_dev->tx_queue_tail;
			tib_dev->tx_queue_tail->next = buf;
			tib_dev->tx_queue_tail = buf;
		}else{
			buf->next = buf->prev = NULL;
			tib_dev->tx_queue = tib_dev->tx_queue_tail = buf;
	       	}*/
	}

exit:
	return TIPC_OK;
}

/**
 * enable_bearer - attach TIPC bearer to an IB interface

 Enregistrement (bind, listen) d'un service RDMA afin permettre la mise en
 place du reseau de connection.

 Mise en place d'un worker visant a tester periodiquement la disponibilite
 de nouveau interlocuteur. En attendant de pouvoir detecter l'arrive de nouveaux
 noeuds, le plus simple reste de tester une plage d'adresse IP.

*/
static
void tipc_ib_do_enable_bearer(struct work_struct *item){
	struct tipc_ib_enable_work_data *data = container_of(item, struct tipc_ib_enable_work_data, work);
	struct rdma_cm_id *listen_id;
	struct sockaddr_in sin;
	struct tipc_bearer *tb_ptr = data->tb_ptr;
	char *driver_name = strchr((const char *)tb_ptr->name, ':') + 1;
	struct ib_device *ibdev;
	struct tipc_ib_device *tipc_ib_dev;
	int i, err;

	/* Look for current IB device */
	ibdev = __ib_device_get_by_name(driver_name);
	if(!ibdev){
		printk("TIPC IB media: Unknown device (%s)\n", driver_name);
		return;
	}

	/* Register tipc_ib_device */
	tipc_ib_dev = tipc_ib_device_lookup(ibdev, data->tb_ptr);
	if(!tipc_ib_dev){
		printk("OOM in tipc_ib_srv_handler\n");
		return;
	}

	/* Allocate PD (IB) */
	tipc_ib_dev->pd = ib_alloc_pd(ibdev);
	if(!tipc_ib_dev->pd){
		printk("SRV error in allocating pd\n");
		return;
	}

	tipc_ib_dev->mr = ib_get_dma_mr(tipc_ib_dev->pd,
					IB_ACCESS_LOCAL_WRITE
					| IB_ACCESS_REMOTE_READ
					| IB_ACCESS_REMOTE_WRITE);
	if(IS_ERR(tipc_ib_dev->mr)){
		printk("SRV error in ib_get_dma_mr\n");
		return;
	}

	set_bit(TIPC_IB_FLAG_ADMIN_UP, &tipc_ib_dev->flags);

	/* Prepare the node in order to receive new connections */
	listen_id = rdma_create_id(tipc_ib_srv_cm_handler, tipc_ib_dev, RDMA_PS_TCP);
	if (IS_ERR(listen_id)){
		printk("tipc_ib_enable_bearer: rdma_create_id: error (%ld)\n", PTR_ERR(listen_id));
		return;
	}

	sin.sin_family	    = AF_INET;
	sin.sin_port	    = htons(20089);
	sin.sin_addr.s_addr = htons(INADDR_ANY);

	err = rdma_bind_addr(listen_id, (struct sockaddr *) &sin);
	if (err){
		printk("tipc_ib_enable_bearer: rdma_bind_addr: error (%d)\n", err);
		return;
	}

	err = rdma_listen(listen_id, KERRIGHED_MAX_NODES);
	if (err){
		printk("tipc_ib_enable_bearer: rdma_listen: error (%d)\n", err);
		return;
	}

	tb_ptr->usr_handle = (void *)tipc_ib_dev;
	tb_ptr->mtu = TIPC_IB_PACKET_SIZE;
	tb_ptr->blocked = 0;

	krgnodes_setall(tipc_ib_dev->ongoing_connections);
	krgnode_clear(0, tipc_ib_dev->ongoing_connections);
	krgnode_clear(kerrighed_node_id, tipc_ib_dev->ongoing_connections);
	krgnode_clear(255, tipc_ib_dev->ongoing_connections);
	for_each_krgnode_mask(i, tipc_ib_dev->ongoing_connections){
		struct tipc_ib_per_node *node;
		if(tipc_ib_dev->nodes[i]){
			printk("tipc_ib_enable_bearer: already initialized entry!!!\n");
			break;
		}

		node = tipc_ib_dev->nodes[i] = tipc_ib_allocate_and_init_per_node(tipc_ib_dev, i);
		//printk("nodes[%d] = %p\n", i, tipc_ib_dev->nodes[i]);

		if(!tipc_ib_dev->nodes[i])
			break;

		node->cm_id = rdma_create_id(tipc_ib_clt_cm_handler, tipc_ib_dev->nodes[i], RDMA_PS_TCP);
		if (IS_ERR(node->cm_id)){
			printk("CLT rdma_create_id: error (%ld)\n", PTR_ERR(node->cm_id));
			continue;
		}

		sin.sin_addr.s_addr = htonl(0xc0a80000+i);

		err = rdma_resolve_addr(node->cm_id, NULL, (struct sockaddr*)&sin,
					5000);
		if(err){
			printk("CLT rdma_resolve_addr: error (%d)\n", err);
			break;
		}

	}

	kfree(data);
}

static
int tipc_ib_enable_bearer(struct tipc_bearer *tb_ptr){
	struct tipc_ib_enable_work_data *data;

	data = kmalloc(sizeof(*data), GFP_ATOMIC);
	if(!data){
		printk("oom in tipc_ib_enable_bearer\n");
		return TIPC_CONN_SHUTDOWN;
	}

	INIT_WORK(&data->work, tipc_ib_do_enable_bearer);
	data->tb_ptr = tb_ptr;

	tb_ptr->usr_handle = NULL;
	tb_ptr->mtu = TIPC_IB_PACKET_SIZE;
	tb_ptr->blocked = 1;

	tipc_ib_media_addr_init(&tb_ptr->addr, kerrighed_node_id);
	schedule_work(&data->work);

	return TIPC_OK;
}

/**
 * disable_bearer - detach TIPC bearer from an IB interface
 */

static
void tipc_ib_disable_bearer(struct tipc_bearer *tb_ptr){
	printk("disable_bearer\n");
}

static
int tipc_ib_msg2addr(struct tipc_media_addr *a, u32 *msg_area){
	tipc_ib_media_addr_init(a, *((kerrighed_node_t*)msg_area));
	return 0;
}

static
int tipc_ib_addr2msg(struct tipc_media_addr *a, u32 *msg_area){
	*((kerrighed_node_t*)msg_area) = *((kerrighed_node_t*)a->value);
	return 0;
}

static
int tipc_ib_addr2str(struct tipc_media_addr *a, char *str_buf, int str_size){
	snprintf(str_buf, str_size, "%d", *((kerrighed_node_t*)a->value));
	return 0;
}

static
int tipc_ib_str2addr(struct tipc_media_addr *a, char *str_buf){
	kerrighed_node_t node;
	sscanf(str_buf, "%d", (u32*)&node);
	tipc_ib_media_addr_init(a, node);
        return 0;
}

/*
 * IB media registration info required by TIPC
 */

static
struct tipc_media tipc_ib_media_info = {
	TIPC_MEDIA_ID_IB,
	"ib",
	TIPC_DEF_LINK_PRI,
	TIPC_DEF_LINK_TOL,
	TIPC_DEF_LINK_WIN,
	tipc_ib_send_msg,
	tipc_ib_enable_bearer,
	tipc_ib_disable_bearer,
	tipc_ib_addr2str,
	tipc_ib_str2addr,
        tipc_ib_msg2addr,
        tipc_ib_addr2msg,
	{{0, 0, 0, TIPC_MEDIA_ID_IB, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	  0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	TIPC_MEDIA_ID_IB, 1}
};

int kdb_fct(int argc, const char **argv){
	int cpuid;
	unsigned int nodeid;
	unsigned int id;

	switch(argc){
	case 2:
		nodeid = simple_strtol(argv[1], NULL, 16);
		id = simple_strtol(argv[2], NULL, 16);
		printk("nodeid=%d id=%x\n", nodeid, id);
		break;
	default:
		printk("incorrect arguments number\n");
		return -1;
	}

	for_each_online_cpu(cpuid){
		struct log *iter;

		for(iter = per_cpu(log_buffer, cpuid); iter<per_cpu(log_index, cpuid); iter++){
			if(iter->id == id && iter->nodeid == nodeid)
				printk("%d %x %d %lx\n", iter->nodeid, iter->id, iter->op, iter->p);
		}
	}
	return 0;
}

int kdb_show(int argc, const char **argv){
	if(argc!=2){
		printk("incorrect arguments number\n");
		return -1;
	}

	if(!strncmp("node", argv[1], 4)){
		u64 p;
		struct tipc_ib_per_node *node;
		p = simple_strtoul(argv[2], NULL, 16);
		node = (void*)p;
		printk("item = %p\n", node);
		printk("nodeid=%d tib_dev=%p\n", node->id, node->tib_dev);
	}else
		printk("Unknown type\n");

	return 0;
}

/**
 * tipc_ib_media_start - activate IB bearer support
 */

int tipc_ib_media_start(void)
{
	int res;

	log_init();
	res = kdb_register("ibd", kdb_fct, "ibd nodeid id", "show trace on one buffer", 3);
	if(res)
		printk("error when registering kdb\n");
	res = kdb_register("d", kdb_show, "d type addr", "d display a typed memory region", 3);
	if(res)
		printk("error when registering kdb\n");

	res = tipc_register_media(&tipc_ib_media_info);
	if (res)
		return res;

	return res;
}

/**
 * tipc_ib_media_stop - deactivate IB bearer support
 */

void tipc_ib_media_stop(void)
{
	flush_scheduled_work();
	unregister_netdevice_notifier(&tipc_ib_notifier);
}
