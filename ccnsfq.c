/*
 * Stochastic Fairness Queueing discipline for CCNx flows.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	
 * Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 * Paolo Viotti, <paolo.viotti@gmail.com>
 */
 
 
 /*	Stochastic Fairness Queuing algorithm.
	=======================================

	Source:
	Paul E. McKenney "Stochastic Fairness Queuing",
	IEEE INFOCOMM'90 Proceedings, San Francisco, 1990.

	Paul E. McKenney "Stochastic Fairness Queuing",
	"Interworking: Research and Experience", v.2, 1991, p.113-131.


	See also:
	M. Shreedhar and George Varghese "Efficient Fair
	Queuing using Deficit Round Robin", Proc. SIGCOMM 95.


	This is not the thing that is usually called (W)FQ nowadays.
	It does not use any timestamp mechanism, but instead
	processes queues in round-robin order.

	ADVANTAGE:

	- It is very cheap. Both CPU and memory requirements are minimal.

	DRAWBACKS:

	- "Stochastic" -> It is not 100% fair.
	When hash collisions occur, several flows are considered as one.

	- "Round-robin" -> It introduces larger delays than virtual clock
	based schemes, and should not be used for isolating interactive
	traffic	from non-interactive. It means, that this scheduler
	should be used as leaf of CBQ or P3, which put interactive traffic
	to higher priority band.

	We still need true WFQ for top level CSZ, but using WFQ
	for the best effort traffic is absolutely pointless:
	SFQ is superior for this purpose.

	IMPLEMENTATION:
	This implementation limits maximal queue length to 128;
	maximal mtu to 2^15-1; number of hash buckets to 1024.
	The only goal of this restrictions was that all data
	fit into one 4K page :-). Struct sfq_sched_data is
	organized in anti-cache manner: all the data for a bucket
	are scattered over different locations. This is not good,
	but it allowed me to put it into 4K.

	It is easy to increase these values, but not in flight.  
*/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <net/ip.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <linux/version.h>

#include "parser.h"

#define DEBUG

#define CCN_MIN_PACKET_SIZE 5

#define CCNSFQ_DEPTH		128	
#define CCNSFQ_HASH_DIVISOR	1024 	/* Max number of hash buckets */

/* This type should contain at least CCNSFQ_DEPTH*2 values */
typedef unsigned char ccnsfq_index;

struct ccnsfq_head
{
	ccnsfq_index	next;
	ccnsfq_index	prev;
};

struct ccnsfq_sched_data
{
/* Parameters */
	int		perturb_period;
	unsigned	quantum;	/* Allotment per round: MUST BE >= MTU */
	int		limit;

/* Variables */
	struct tcf_proto *filter_list;
	struct timer_list perturb_timer;
	u32		perturbation;
	ccnsfq_index	tail;		/* Index of current slot in round */
	ccnsfq_index	max_depth;	/* Maximal depth */

	ccnsfq_index	ht[CCNSFQ_HASH_DIVISOR];	/* Hash table */
	ccnsfq_index	next[CCNSFQ_DEPTH];	/* Active slots link */
	short		allot[CCNSFQ_DEPTH];	/* Current allotment per slot */
	unsigned short	hash[CCNSFQ_DEPTH];	/* Hash value indexed by slots */
	struct sk_buff_head	qs[CCNSFQ_DEPTH];		/* Slot queue */
	struct ccnsfq_head	dep[CCNSFQ_DEPTH*2];	/* Linked list of slots, indexed by depth */
};


static unsigned ccnsfq_hash(struct ccnsfq_sched_data *q, struct sk_buff *skb)
{
	u32 h = 0;
	char * dataptr;
	char * name;
	int len = 0;
	u8 ccn = 0;

	if (skb->protocol == htons(ETH_P_IP)){
		struct iphdr * l3h = ip_hdr(skb);
		#ifdef DEBUG
			printk(KERN_INFO "===== IP Packet: saddr=%u.%u.%u.%u, daddr=%u.%u.%u.%u", NIPQUAD(l3h->saddr), NIPQUAD(l3h->daddr));
		#endif			
		if (l3h->protocol == IPPROTO_UDP){
			struct udphdr *udph = udp_hdr(skb);
			#ifdef DEBUG
				printk(KERN_INFO "UDP datagram: srcport=%u, dstport=%u, length=%u", ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len));
			#endif
			dataptr = skb->transport_header + 8;
			len = ntohs(udph->len)-8;
			if ((dataptr[0]=='\x01' && dataptr[1] =='\xD2') || (dataptr[0]=='\x04' && dataptr[1]=='\x82'))
				if (len > CCN_MIN_PACKET_SIZE){
					name = parse(dataptr, len);
					if (strcmp(name, "ERROR")!=0) ccn=1;
				}
		}
		else if (l3h->protocol == IPPROTO_IPIP){
			struct iphdr * ipiph = (struct iphdr *) skb_transport_header(skb); // see struct iphdr *ipip_hdr(const struct sk_buff *skb) in ip.h
			#ifdef DEBUG
				printk(KERN_INFO "IPIP tunnel: saddr=%u.%u.%u.%u, daddr=%u.%u.%u.%u", NIPQUAD(ipiph->saddr), NIPQUAD(ipiph->daddr));
			#endif
			if (ipiph->protocol == IPPROTO_UDP){				
				struct udphdr *udph = (struct udphdr *) (skb->transport_header + 20);	// TRUCE
				#ifdef DEBUG
					printk(KERN_INFO "UDP datagram: srcport=%u, dstport=%u, length=%u", ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len));
				#endif
				dataptr = skb->transport_header + 20 + 8; // IP encapsulation + UDP header
				len = ntohs(udph->len)-8;
				if ((dataptr[0]=='\x01' && dataptr[1] =='\xD2') || (dataptr[0]=='\x04' && dataptr[1]=='\x82'))
					if (len > CCN_MIN_PACKET_SIZE){
						name = parse(dataptr, len);
						if (strcmp(name, "ERROR")!=0) ccn=1;
					}
			}
		}
	}

	if (ccn){               // regular CCN packet, enqueued by name
		if (dataptr[0]=='\x01' && dataptr[1] =='\xD2'){  // it's a CCN Interest
				h = jhash((u8 *)name, 13, 0) & (CCNSFQ_HASH_DIVISOR - 1);
				#ifdef DEBUG
					printk(KERN_INFO "Interest, Name: %s, jHash: %3X", name, h);
				#endif
		}
		else{                                            // it's a CCN Data
				h = jhash((u8 *)name, 13, 1) & (CCNSFQ_HASH_DIVISOR - 1);   
				#ifdef DEBUG
					printk(KERN_INFO "Data, Name: %s, jHash: %3X", name, h);
				#endif
		}
		kfree(name); name=NULL;
	}       
	else{   				// not CCN packet, enqueued in a single queue
		name = "NO_CCN_Packet";
		h = jhash((u8 *)name, 13, 0) & (CCNSFQ_HASH_DIVISOR - 1);
		#ifdef DEBUG
			printk(KERN_INFO "No_CCN, Name: %s, jHash: %3X", name, h);
		#endif
	}
		
	return h;
}

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,31)
	static int sfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
					struct nlattr **tca, unsigned long *arg)
	{
		return -EOPNOTSUPP;
	}
#endif

static unsigned int ccnsfq_classify(struct sk_buff *skb, struct Qdisc *sch,
				 int *qerr)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	struct tcf_result res;
	int result;

	//printk(KERN_INFO "CCNv: in the classify function\n");

	if (TC_H_MAJ(skb->priority) == sch->handle &&
	    TC_H_MIN(skb->priority) > 0 &&
	    TC_H_MIN(skb->priority) <= CCNSFQ_HASH_DIVISOR)
		return TC_H_MIN(skb->priority);

	if (!q->filter_list)
		return ccnsfq_hash(q, skb) + 1;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	result = tc_classify(skb, q->filter_list, &res);
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
		case TC_ACT_SHOT:
			return 0;
		}
#endif
		if (TC_H_MIN(res.classid) <= CCNSFQ_HASH_DIVISOR)
			return TC_H_MIN(res.classid);
	}
	return 0;
}

static inline void ccnsfq_link(struct ccnsfq_sched_data *q, ccnsfq_index x)
{
	ccnsfq_index p, n;
	int d = q->qs[x].qlen + CCNSFQ_DEPTH;

	p = d;
	n = q->dep[d].next;
	q->dep[x].next = n;
	q->dep[x].prev = p;
	q->dep[p].next = q->dep[n].prev = x;
}

static inline void ccnsfq_dec(struct ccnsfq_sched_data *q, ccnsfq_index x)
{
	ccnsfq_index p, n;

	n = q->dep[x].next;
	p = q->dep[x].prev;
	q->dep[p].next = n;
	q->dep[n].prev = p;

	if (n == p && q->max_depth == q->qs[x].qlen + 1)
		q->max_depth--;

	ccnsfq_link(q, x);
}

static inline void ccnsfq_inc(struct ccnsfq_sched_data *q, ccnsfq_index x)
{
	ccnsfq_index p, n;
	int d;

	n = q->dep[x].next;
	p = q->dep[x].prev;
	q->dep[p].next = n;
	q->dep[n].prev = p;
	d = q->qs[x].qlen;
	if (q->max_depth < d)
		q->max_depth = d;

	ccnsfq_link(q, x);
}

static unsigned int ccnsfq_drop(struct Qdisc *sch)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	ccnsfq_index d = q->max_depth;
	struct sk_buff *skb;
	unsigned int len;

	/* Queue is full! Find the longest slot and
	   drop a packet from it */

	if (d > 1) {
		ccnsfq_index x = q->dep[d + CCNSFQ_DEPTH].next;
		skb = q->qs[x].prev;
		len = qdisc_pkt_len(skb);
		__skb_unlink(skb, &q->qs[x]);
		kfree_skb(skb);
		ccnsfq_dec(q, x);
		sch->q.qlen--;
		sch->qstats.drops++;
		sch->qstats.backlog -= len;
		return len;
	}

	if (d == 1) {
		/* It is difficult to believe, but ALL THE SLOTS HAVE LENGTH 1. */
		d = q->next[q->tail];
		q->next[q->tail] = q->next[d];
		q->allot[q->next[d]] += q->quantum;
		skb = q->qs[d].prev;
		len = qdisc_pkt_len(skb);
		__skb_unlink(skb, &q->qs[d]);
		kfree_skb(skb);
		ccnsfq_dec(q, d);
		sch->q.qlen--;
		q->ht[q->hash[d]] = CCNSFQ_DEPTH;
		sch->qstats.drops++;
		sch->qstats.backlog -= len;
		return len;
	}

	return 0;
}

static int
ccnsfq_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	unsigned int hash;
	ccnsfq_index x;
	int uninitialized_var(ret);

	hash = ccnsfq_classify(skb, sch, &ret);
	if (hash == 0) {
		if (ret & __NET_XMIT_BYPASS)
			sch->qstats.drops++;
		kfree_skb(skb);
		return ret;
	}
	hash--;

	x = q->ht[hash];
	if (x == CCNSFQ_DEPTH) {
		q->ht[hash] = x = q->dep[CCNSFQ_DEPTH].next;
		q->hash[x] = hash;
	}

	/* If selected queue has length q->limit, this means that
	 * all another queues are empty and that we do simple tail drop,
	 * i.e. drop _this_ packet.
	 */
	if (q->qs[x].qlen >= q->limit)
		return qdisc_drop(skb, sch);

	sch->qstats.backlog += qdisc_pkt_len(skb);
	__skb_queue_tail(&q->qs[x], skb);
	ccnsfq_inc(q, x);
	if (q->qs[x].qlen == 1) {		/* The flow is new */
		if (q->tail == CCNSFQ_DEPTH) {	/* It is the first flow */
			q->tail = x;
			q->next[x] = x;
			q->allot[x] = q->quantum;
		} else {
			q->next[x] = q->next[q->tail];
			q->next[q->tail] = x;
			q->tail = x;
		}
	}
	if (++sch->q.qlen <= q->limit) {
		sch->bstats.bytes += qdisc_pkt_len(skb);
		sch->bstats.packets++;
		return 0;
	}

	ccnsfq_drop(sch);
	return NET_XMIT_CN;
}

static struct sk_buff *
ccnsfq_peek(struct Qdisc *sch)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	ccnsfq_index a;

	/* No active slots */
	if (q->tail == CCNSFQ_DEPTH)
		return NULL;

	a = q->next[q->tail];
	return skb_peek(&q->qs[a]);
}

static struct sk_buff *
ccnsfq_dequeue(struct Qdisc *sch)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;
	ccnsfq_index a, old_a;

	/* No active slots */
	if (q->tail == CCNSFQ_DEPTH)
		return NULL;

	a = old_a = q->next[q->tail];

	/* Grab packet */
	skb = __skb_dequeue(&q->qs[a]);
	ccnsfq_dec(q, a);
	sch->q.qlen--;
	sch->qstats.backlog -= qdisc_pkt_len(skb);

	/* Is the slot empty? */
	if (q->qs[a].qlen == 0) {
		q->ht[q->hash[a]] = CCNSFQ_DEPTH;
		a = q->next[a];
		if (a == old_a) {
			q->tail = CCNSFQ_DEPTH;
			return skb;
		}
		q->next[q->tail] = a;
		q->allot[a] += q->quantum;
	} else if ((q->allot[a] -= qdisc_pkt_len(skb)) <= 0) {
		q->tail = a;
		a = q->next[a];
		q->allot[a] += q->quantum;
	}
	return skb;
}

static void
ccnsfq_reset(struct Qdisc *sch)
{
	struct sk_buff *skb;

	while ((skb = ccnsfq_dequeue(sch)) != NULL)
		kfree_skb(skb);
}

static void ccnsfq_perturbation(unsigned long arg)
{
	struct Qdisc *sch = (struct Qdisc *)arg;
	struct ccnsfq_sched_data *q = qdisc_priv(sch);

	q->perturbation = net_random();

	if (q->perturb_period)
		mod_timer(&q->perturb_timer, jiffies + q->perturb_period);
}

static int ccnsfq_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	struct tc_sfq_qopt *ctl = nla_data(opt);
	unsigned int qlen;

	if (opt->nla_len < nla_attr_size(sizeof(*ctl)))
		return -EINVAL;

	sch_tree_lock(sch);
	q->quantum = ctl->quantum ? : psched_mtu(qdisc_dev(sch));
	q->perturb_period = ctl->perturb_period * HZ;
	if (ctl->limit)
		q->limit = min_t(u32, ctl->limit, CCNSFQ_DEPTH - 1);

	qlen = sch->q.qlen;
	while (sch->q.qlen > q->limit)
		ccnsfq_drop(sch);
	qdisc_tree_decrease_qlen(sch, qlen - sch->q.qlen);

	del_timer(&q->perturb_timer);
	if (q->perturb_period) {
		mod_timer(&q->perturb_timer, jiffies + q->perturb_period);
		q->perturbation = net_random();
	}
	sch_tree_unlock(sch);
	return 0;
}

static int ccnsfq_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	int i;

	q->perturb_timer.function = ccnsfq_perturbation;
	q->perturb_timer.data = (unsigned long)sch;
	init_timer_deferrable(&q->perturb_timer);

	for (i = 0; i < CCNSFQ_HASH_DIVISOR; i++)
		q->ht[i] = CCNSFQ_DEPTH;

	for (i = 0; i < CCNSFQ_DEPTH; i++) {
		skb_queue_head_init(&q->qs[i]);
		q->dep[i + CCNSFQ_DEPTH].next = i + CCNSFQ_DEPTH;
		q->dep[i + CCNSFQ_DEPTH].prev = i + CCNSFQ_DEPTH;
	}

	q->limit = CCNSFQ_DEPTH - 1;
	q->max_depth = 0;
	q->tail = CCNSFQ_DEPTH;
	if (opt == NULL) {
		q->quantum = psched_mtu(qdisc_dev(sch));
		q->perturb_period = 0;
		q->perturbation = net_random();
	} else {
		int err = ccnsfq_change(sch, opt);
		if (err)
			return err;
	}

	for (i = 0; i < CCNSFQ_DEPTH; i++)
		ccnsfq_link(q, i);
	return 0;
}

static void ccnsfq_destroy(struct Qdisc *sch)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);

	tcf_destroy_chain(&q->filter_list);
	q->perturb_period = 0;
	del_timer_sync(&q->perturb_timer);
}

static int ccnsfq_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_sfq_qopt opt;
	
	opt.quantum = q->quantum;
	opt.perturb_period = q->perturb_period / HZ;

	opt.limit = q->limit;
	opt.divisor = CCNSFQ_HASH_DIVISOR;
	opt.flows = q->limit;

	NLA_PUT(skb, TCA_OPTIONS, sizeof(opt), &opt);

	return skb->len;

	nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static unsigned long ccnsfq_get(struct Qdisc *sch, u32 classid)
{
	return 0;
}

static struct tcf_proto **ccnsfq_find_tcf(struct Qdisc *sch, unsigned long cl)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return &q->filter_list;
}

static int ccnsfq_dump_class(struct Qdisc *sch, unsigned long cl,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	tcm->tcm_handle |= TC_H_MIN(cl);
	return 0;
}

static int ccnsfq_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				struct gnet_dump *d)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	ccnsfq_index idx = q->ht[cl-1];
	struct gnet_stats_queue qs = { .qlen = q->qs[idx].qlen };
	struct tc_sfq_xstats xstats = { .allot = q->allot[idx] };

	if (gnet_stats_copy_queue(d, &qs) < 0)
		return -1;
	return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
}

static void ccnsfq_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct ccnsfq_sched_data *q = qdisc_priv(sch);
	unsigned int i;

	if (arg->stop)
		return;

	for (i = 0; i < CCNSFQ_HASH_DIVISOR; i++) {
		if (q->ht[i] == CCNSFQ_DEPTH ||
		    arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, i + 1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static const struct Qdisc_class_ops ccnsfq_class_ops = {
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,31)
	.change		=	sfq_change_class,
#endif
	.get		=	ccnsfq_get,
	.tcf_chain	=	ccnsfq_find_tcf,
	.dump		=	ccnsfq_dump_class,
	.dump_stats	=	ccnsfq_dump_class_stats,
	.walk		=	ccnsfq_walk,
};

static struct Qdisc_ops ccnsfq_qdisc_ops __read_mostly = {
	.cl_ops		=	&ccnsfq_class_ops,
	.id			=	"ccnsfq", 
	.priv_size	=	sizeof(struct ccnsfq_sched_data),
	.enqueue	=	ccnsfq_enqueue,
	.dequeue	=	ccnsfq_dequeue,
	.peek		=	ccnsfq_peek,
	.drop		=	ccnsfq_drop,
	.init		=	ccnsfq_init,
	.reset		=	ccnsfq_reset,
	.destroy	=	ccnsfq_destroy,
	.change		=	NULL,
	.dump		=	ccnsfq_dump,
	.owner		=	THIS_MODULE,
};

static int __init ccnsfq_module_init(void)
{
	return register_qdisc(&ccnsfq_qdisc_ops);
}
static void __exit ccnsfq_module_exit(void)
{
	unregister_qdisc(&ccnsfq_qdisc_ops);
}
module_init(ccnsfq_module_init)
module_exit(ccnsfq_module_exit)
MODULE_LICENSE("GPL");
