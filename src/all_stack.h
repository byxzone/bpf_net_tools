#ifndef __ALL_STACK_H
#define __ALL_STACK_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

#define max_trace_func 10

struct packet_tuple {
    u32 cpu;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 seq;
    u32 ack;
};

struct netstack_info {
    u64 time_info[max_trace_func];
    struct packet_tuple pkt_tuple;
};

#endif