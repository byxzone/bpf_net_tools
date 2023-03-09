#include "vmlinux.h"
#include "maps.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "all_stack.h"

#define MARK_KFUNC_TIME(kfunc_name,kunc_name_quot,kfunc_id) \
SEC("kprobe/"kunc_name_quot) \
int BPF_KPROBE(kfunc_name,struct sk_buff *skb){ \
    if (skb == NULL){ \
        return 0; \
    } \
    struct iphdr *ip = skb_to_iphdr(skb); \
    if(BPF_CORE_READ(ip,protocol) == IPPROTO_TCP){ \
        struct tcphdr *tcp = skb_to_tcphdr(skb); \
        u32 cpu = bpf_get_smp_processor_id(); \
        struct netstack_info *p_sinfo = bpf_map_lookup_elem(&stackinfo,&cpu); \
            if(p_sinfo == NULL) \
                return 0; \
        if(BPF_CORE_READ(tcp,seq) != __bpf_ntohl(p_sinfo->pkt_tuple.seq)) \
            return 0; \
        p_sinfo->time_info[kfunc_id] = bpf_ktime_get_ns(); \
    } \
    return 0;\
}

const volatile int filter_dport = 0;
const volatile int filter_sport = 0;

#define FILTER_SPORT if(filter_sport){if (__bpf_ntohs(BPF_CORE_READ(tcp,source)) != filter_sport) { return 0; }}
#define FILTER_DPORT if(filter_dport){if (__bpf_ntohs(BPF_CORE_READ(tcp,dest)) != filter_dport) { return 0; }}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, u32);
	__type(value, struct netstack_info);
} stackinfo SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

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
    int err = 0;
    if (protocol == 8){ // Protocol is IP
        struct iphdr *ip = skb_to_iphdr(skb);
        if(BPF_CORE_READ(ip,protocol) == IPPROTO_TCP){
            struct tcphdr *tcp = skb_to_tcphdr(skb); 
            FILTER_SPORT
            FILTER_DPORT
            u32 cpu = bpf_get_smp_processor_id();
            struct netstack_info *p_sinfo = bpf_map_lookup_elem(&stackinfo,&cpu);
            if(p_sinfo == NULL){
                struct netstack_info zero = {};
                bpf_map_update_elem(&stackinfo,&cpu, &zero, BPF_NOEXIST);
                p_sinfo = bpf_map_lookup_elem(&stackinfo,&cpu);
                if(p_sinfo == NULL)
                    return 0;
            }
            else{
                struct netstack_info *data;
                data = bpf_ringbuf_reserve(&rb, sizeof(*data), 0);
                if (!data){
		            return 0;
                }
                bpf_probe_read_kernel(data,sizeof(*data),p_sinfo);
                //bpf_printk("%u,%u",data->pkt_tuple.seq,data->pkt_tuple.ack);
                bpf_ringbuf_submit(data, 0);
            }
            p_sinfo->time_info[0] = bpf_ktime_get_ns();
            get_pkt_tuple(&p_sinfo->pkt_tuple, ip, tcp);
            p_sinfo->pkt_tuple.cpu = cpu;
        }
    }
    return 0;
}

MARK_KFUNC_TIME(ip_rcv,"ip_rcv",1);
MARK_KFUNC_TIME(ip_rcv_finish,"ip_rcv_finish",2);
MARK_KFUNC_TIME(tcp_v4_rcv,"tcp_v4_rcv",3);


char LICENSE[] SEC("license") = "Dual BSD/GPL";