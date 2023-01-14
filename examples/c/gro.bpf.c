// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "list.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define UDP_GRO_CNT_MAX 64

#define ETHER_HDR_LEN 14

#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
    return skb->head + skb->transport_header;
}

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
    return (struct udphdr *)skb_transport_header(skb);
}

static inline unsigned int skb_gro_len(const struct sk_buff *skb)
{
    return skb->len - NAPI_GRO_CB(skb)->data_offset;
}

SEC("fentry/udp_gro_receive_segment")
int BPF_PROG(udp_gro_receive_segment, struct list_head *head, struct sk_buff *skb)
{
    struct napi_gro_cb *cb = (struct napi_gro_cb *)(skb)->cb;
//    unsigned int off = cb->data_offset; // udp header offset
    void *data = (void *)(long)skb->data;
    struct eth_hdr *eth = data;
    struct iphdr *iph = data + ETHER_HDR_LEN;
    struct udphdr *udp = data + ETHER_HDR_LEN + sizeof(*iph);

    if (!udp->check)
        bpf_printk(": flush\n");

//    unsigned int ulen = bpf_ntohs(uh->len);
//    if (ulen <= sizeof(*uh) || ulen != skb_gro_len(skb)) {
//        return 0;
//    }
//
//    struct sk_buff *p;
//    struct udphdr *uh2;
//    list_for_each_entry(p, head, list) {
//        if (!NAPI_GRO_CB(p)->same_flow)
//            continue;
//
//        uh2 = udp_hdr(p);
//
//        /* Match ports only, as csum is always non zero */
//        if ((*(u32 *)&uh->source != *(u32 *)&uh2->source)) {
//            continue;
//        }
//
//        if (NAPI_GRO_CB(skb)->is_flist != NAPI_GRO_CB(p)->is_flist) {
//            return 0;
//        }
//
//        if (ulen > bpf_ntohs(uh2->len)) {
//            return 0;
//        }
//
//        break;
//    }
//
//    if (&p->list == head) {
//        return 0;
//    }
//
//    if (NAPI_GRO_CB(skb)->is_flist) {
//        bpf_printk("udp_gro_receive_segment: skb_gro_receive_list\n");
//    } else {
//        bpf_printk("%s: skb_gro_receive\n", __func__);
//    }
//
//    if (ulen != bpf_ntohs(uh2->len) || NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX) {
//        bpf_printk(": flush\n");
//    }



    return 0;
}
