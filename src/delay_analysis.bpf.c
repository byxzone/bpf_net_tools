#include "vmlinux.h"
#include "maps.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "delay_analysis.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct packet_tuple);
	__type(value, struct ktime_info);
} in_timestamps SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int sampling = 0;

#define SAMPLING  if(sampling){ if (((pkt_tuple.seq + pkt_tuple.ack + BPF_CORE_READ(skb,len)) << (32-sampling) >> (32-sampling)) != ((0x01 << sampling) - 1)) { return 0;}}
#define FILTER_DPORT if(filter_dport){if (pkt_tuple.dport != filter_dport) { return 0; }}
#define FILTER_SPORT if(filter_sport){if (pkt_tuple.sport != filter_sport) { return 0; }}

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb){
    return (struct tcphdr *)((BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,transport_header)));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb){
    return (struct iphdr *)(BPF_CORE_READ(skb,head) + BPF_CORE_READ(skb,network_header));
}

static void get_pkt_tuple(struct packet_tuple *pkt_tuple, struct iphdr *ip, struct tcphdr *tcp){
    pkt_tuple->saddr = BPF_CORE_READ(ip,saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip,daddr);
    u16 sport = BPF_CORE_READ(tcp,source);
    u16 dport = BPF_CORE_READ(tcp,dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp,seq);
    u32 ack = BPF_CORE_READ(tcp,ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);
} 

SEC("kprobe/eth_type_trans")
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb){
    const struct ethhdr* eth = (struct ethhdr*)BPF_CORE_READ(skb,data);
    u16 protocol = BPF_CORE_READ(eth, h_proto); 

    if (protocol == 8){ // Protocol is IP
        struct iphdr *ip = (struct iphdr *)(BPF_CORE_READ(skb,data) + 14);
        // TODO options in hdr
        struct tcphdr *tcp = (struct tcphdr *)(BPF_CORE_READ(skb,data) + 34);
        struct packet_tuple pkt_tuple = {};
        get_pkt_tuple(&pkt_tuple, ip, tcp);
        
        SAMPLING
        FILTER_DPORT
        FILTER_SPORT
        
        struct ktime_info *tinfo, zero={}; 
        
        tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&in_timestamps,&pkt_tuple, &zero);
        if (tinfo == NULL){
            return 0;
        }
        tinfo->mac_time = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("kprobe/ip_rcv_core")
int BPF_KPROBE(ip_rcv_core,struct sk_buff *skb){
    if (skb == NULL){
        return 0;
    }
    
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT

    struct ktime_info *tinfo;
    
    if ((tinfo = bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
        return 0;
    }
    
    tinfo->ip_time = bpf_ktime_get_ns();
    
    return 0;
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv,struct sk_buff *skb){
    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT

    struct ktime_info *tinfo;
    if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
        return 0;
    }
    tinfo->tcp_time = bpf_ktime_get_ns();
    
    return 0;
}

SEC("kprobe/skb_copy_datagram_iter")
int BPF_KPROBE(skb_copy_datagram_iter,struct sk_buff *skb){
    if (skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {};
    get_pkt_tuple(&pkt_tuple, ip, tcp);

    SAMPLING
    FILTER_DPORT
    FILTER_SPORT
    
    struct ktime_info *tinfo;
    if ((tinfo =  bpf_map_lookup_elem(&in_timestamps,&pkt_tuple)) == NULL){
        return 0;
    }

    tinfo->app_time = bpf_ktime_get_ns();

    struct data_t *data;
    data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
    if (!data)
		return 0;

    data->mac_timestamp = tinfo->mac_time;
    data->total_time = tinfo->app_time - tinfo->mac_time;
    data->mac_time = tinfo->ip_time - tinfo->mac_time;
    data->ip_time = tinfo->tcp_time - tinfo->ip_time;
    data->tcp_time = tinfo->app_time - tinfo->tcp_time;

    data->saddr = pkt_tuple.saddr;
    data->daddr = pkt_tuple.daddr;
    data->sport = pkt_tuple.sport;
    data->dport = pkt_tuple.dport;
    data->seq = pkt_tuple.seq;
    data->ack = pkt_tuple.ack;
    bpf_map_delete_elem(&in_timestamps,&pkt_tuple);
    bpf_ringbuf_submit(data, 0);
    return 0;
}