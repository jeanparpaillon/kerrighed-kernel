
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/skbuff.h>
#include <linux/socket.h>

#include <net/sock.h>

#include <kerrighed/checkpoint_sock.h>
#include "checkpoint_skbuff.h"
#include "checkpoint_utils.h"


static int krgip_checkpoint_skbfrag(struct epm_action *action, ghost_t *ghost,
				    struct sk_buff *skb, skb_frag_t *frag)
{
	int ret = 0;
        char *page_addr;

	page_addr = (char *)kmap(frag->page);
	if (!page_addr) {
		ret = -EINVAL;
		goto out;
	}

	KRGIP_CKPT_COPY(action, ghost, frag->page_offset, ret);
	KRGIP_CKPT_DATA(action, ghost, page_addr, frag->size, ret);

        kunmap(frag->page);
out:
	return ret;
}


static int krgip_export_skbfrag(struct epm_action *action, ghost_t *ghost,
				struct sk_buff *skb, skb_frag_t *frag)
{
	int ret;

	ret = krgip_checkpoint_skbfrag(action, ghost, skb, frag);

	put_page(frag->page);

	return ret;
}

static int krgip_import_skbfrag(struct epm_action *action, ghost_t *ghost,
				struct sk_buff *skb, skb_frag_t *frag)
{
	int ret;

	frag->page = alloc_page(GFP_KERNEL);
	if (!frag->page) {
		ret = -ENOMEM;
		goto out;
	}

	ret = krgip_checkpoint_skbfrag(action, ghost, skb, frag);
	if (ret)
		__free_page(frag->page);

out:
	return ret;
}

static int krgip_checkpoint_skbinfo(struct epm_action *action,
				    ghost_t *ghost, struct sk_buff *skb)
{
#ifndef NET_SKBUFF_DATA_USES_OFFSET
	unsigned int transport_header, network_header, mac_header, tail;
#endif
	unsigned int header_len;
	int ret = 0;

	KRGIP_CKPT_COPY(action, ghost, skb->mac_len, ret);
	KRGIP_CKPT_COPY(action, ghost, skb->len, ret);
	KRGIP_CKPT_COPY(action, ghost, skb->data_len, ret);

	if (KRGIP_CKPT_ISSRC(action)) {
		header_len = skb->data - skb->head;
	}
	KRGIP_CKPT_COPY(action, ghost, header_len, ret);
	if (KRGIP_CKPT_ISDST(action)) {
		skb->data = skb->head + header_len;
	}

#ifdef NET_SKBUFF_DATA_USES_OFFSET
	KRGIP_CKPT_COPY(action, ghost, skb->transport_header, ret);
	KRGIP_CKPT_COPY(action, ghost, skb->network_header, ret);
	KRGIP_CKPT_COPY(action, ghost, skb->mac_header, ret);
	KRGIP_CKPT_COPY(action, ghost, skb->tail, ret);
#else
	if (KRGIP_CKPT_ISSRC(action)) {
		transport_header = skb->transport_header - skb->head;
		network_header = skb->network_header - skb->head;
		mac_header = skb->mac_header - skb->head;
		tail = ((unsigned long) skb->tail - (unsigned long) skb->head);
	}
	KRGIP_CKPT_COPY(action, ghost, transport_header, ret);
	KRGIP_CKPT_COPY(action, ghost, network_header, ret);
	KRGIP_CKPT_COPY(action, ghost, mac_header, ret);
	KRGIP_CKPT_COPY(action, ghost, tail, ret);
	if (KRGIP_CKPT_ISDST(action)) {
		skb->transport_header = skb->head + transport_header;
		skb->network_header = skb->head + network_header;
		skb->mac_header = skb->head + mac_header;
		skb->tail = skb->head + tail;
	}
#endif
	KRGIP_CKPT_COPY(action, ghost, skb->cb, ret);

	KRGIP_CKPT_COPY(action, ghost, skb_shinfo(skb)->nr_frags, ret);

	return ret;
}


static int krgip_import_skbinfo(struct epm_action *action,
				ghost_t *ghost, struct sk_buff *skb)
{
	int ret;

	ret = krgip_checkpoint_skbinfo(action, ghost, skb);
	if (ret)
		goto out_err;

	if ((skb->mac_header + skb->mac_len != skb->network_header) ||
	    (skb->network_header > skb->tail) ||
	    (skb->transport_header > skb->tail) ||
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	    (skb->data > skb->head + skb->tail) ||
#else
	    (skb->data > skb->tail) ||
#endif
	    (skb->len > SKB_MAX_ALLOC)
	) {
		printk("Bad lengths in skb structure\n");
		ret = -EINVAL;
		goto out_err;
	}

/*	skb_set_transport_header(skb, h->transport_header);
	skb_set_network_header(skb, h->network_header);
	skb_set_mac_header(skb, h->mac_header);*/

out_err:
	return 0;
}

static int krgip_export_skbinfo(struct epm_action *action,
				ghost_t *ghost, struct sk_buff *skb)
{
	int ret = 0;

	ret = krgip_checkpoint_skbinfo(action, ghost, skb);

	return ret;
}

int krgip_import_buff(struct epm_action *action, ghost_t *ghost,
		      struct sk_buff *skb)
{
	int ret = 0;
	int i;
	struct skb_shared_info *skbfrags;

	ret = krgip_import_skbinfo(action, ghost, skb);
	if (ret)
		goto out;

	skbfrags = skb_shinfo(skb);

	for(i=0; i<skbfrags->nr_frags; i++) {
		ret = krgip_import_skbfrag(action, ghost, skb, &skbfrags->frags[i]);
		if (ret)
			goto out;
	}

out:
	return ret;
}

int krgip_export_buff(struct epm_action *action, ghost_t *ghost,
		      struct sk_buff *skb)
{
	int ret = 0;
	int i;
	struct skb_shared_info *skbfrags;

	ret = krgip_export_skbinfo(action, ghost, skb);
	if (ret)
		goto out;

	skbfrags = skb_shinfo(skb);

	for(i=0; i<skbfrags->nr_frags; i++) {
		ret = krgip_export_skbfrag(action, ghost, skb, &skbfrags->frags[i]);
		if (ret)
			goto out;
	}

out:
	return ret;
}

int krgip_import_buffers(struct epm_action *action, ghost_t *ghost,
			 struct sk_buff_head *skblist)
{
	int ret = 0;
	unsigned int count = 0;
	unsigned int skb_truesize = 0;
	struct sk_buff *new_skb;

	ret = ghost_read(ghost, &count, sizeof(count));
	if (ret)
		goto out;

	for (;count>0;count--) {
		ret = ghost_read(ghost, &skb_truesize, sizeof(skb_truesize));
		if (!ret)
			goto out;

		new_skb = alloc_skb(skb_truesize - sizeof(struct sk_buff), GFP_KERNEL);
		if (!new_skb) {
			ret = -ENOMEM;
			goto out_free;
		}

		ret = krgip_import_buff(action, ghost, new_skb);
		if (ret)
			goto out_free;
	}

out:
	if (ret)
		pr_debug("import_buffers() returned error %d\n", ret);
	return ret;

out_free:
	goto out;
}

int krgip_export_buffers(struct epm_action *action, ghost_t *ghost,
			 struct sk_buff_head *skblist)
{
	int ret = 0;
	unsigned int count = 0;
	struct sk_buff *pos;

	spin_lock_bh(&skblist->lock);
	skb_queue_walk(skblist, pos)
		count++;

	ret = ghost_write(ghost, &count, sizeof(count));
	if (ret)
		goto out;

	skb_queue_walk(skblist, pos) {
		BUG_ON(!count);
		count--;
		ret = ghost_read(ghost, &pos->truesize, sizeof(pos->truesize));
		if (!ret)
			goto out;

		ret = krgip_export_buff(action, ghost, pos);
		if (ret)
			goto out;
		consume_skb(pos);
	}
	BUG_ON(count);

out:
	spin_unlock_bh(&skblist->lock);
	if (ret)
		pr_debug("export_buffers() returned error %d\n", ret);
	return ret;
}

