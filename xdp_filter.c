#include <uapi/linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <linux/hash.h>

#define IPPROTO_TCP 6

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80

#define COOKIE_SECRET 0xdeadbeef

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;
    union {
        __u16 flags;
        struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
            __u16 res1:4,
                  doff:4,
                  fin:1,
                  syn:1,
                  rst:1,
                  psh:1,
                  ack:1,
                  urg:1,
                  ece:1,
                  cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
            __u16 doff:4,
                  res1:4,
                  cwr:1,
                  ece:1,
                  urg:1,
                  ack:1,
                  psh:1,
                  rst:1,
                  syn:1,
                  fin:1;
#endif
        };
    };
    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

#define INTERNAL static __attribute__((always_inline))

#ifndef NDEBUG
#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)
#else
#define LOG(fmt, ...)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memset
#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#endif

struct Packet {
    struct xdp_md *ctx;
    struct ethhdr *ether;
    struct iphdr  *ip;
    struct tcphdr *tcp;
};

struct FourTuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

INTERNAL __u32 hash_crc32(__u32 data, __u32 seed) {
    return hash_32(seed ^ data, 32);
}

INTERNAL __u32 cookie_hash(struct FourTuple t) {
    __u32 h = COOKIE_SECRET;
    h = hash_crc32(t.saddr, h);
    h = hash_crc32(t.daddr, h);
    h = hash_crc32(((__u32)t.sport << 16) | t.dport, h);
    return h;
}

INTERNAL __u32 cookie_make(struct FourTuple t, __u32 client_seq) {
    return client_seq + cookie_hash(t);
}

INTERNAL int cookie_check(struct FourTuple t, __u32 client_seq, __u32 ack_seq) {
    return cookie_make(t, client_seq) == ack_seq;
}

#define MAX_CSUM_WORDS 32
#define MAX_CSUM_BYTES (MAX_CSUM_WORDS * 2)

INTERNAL __u32 sum16(const void *data, __u32 size, const void *data_end) {
    __u32 s = 0;
#pragma unroll
    for (__u32 i = 0; i < MAX_CSUM_WORDS; i++) {
        if (2 * i >= size)
            return s;
        if (data + 2 * i + 2 > data_end)
            return 0;
        s += ((__u16 *)data)[i];
    }
    return s;
}

INTERNAL __u32 sum16_32(__u32 v) {
    return (v >> 16) + (v & 0xffff);
}

INTERNAL __u16 carry(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

INTERNAL int process_tcp_syn(struct Packet *packet) {
    struct xdp_md *ctx = packet->ctx;
    struct ethhdr *ether = packet->ether;
    struct iphdr *ip = packet->ip;
    struct tcphdr *tcp = packet->tcp;
    const void *data_end = (void *)ctx->data_end;

    __u32 ip_len = ip->ihl * 4;
    if ((void *)ip + ip_len > data_end)
        return XDP_DROP;

    __u32 tcp_len = tcp->doff * 4;
    if ((void *)tcp + tcp_len > data_end)
        return XDP_DROP;

    struct FourTuple tuple = {
        ip->saddr,
        ip->daddr,
        tcp->source,
        tcp->dest
    };

    __u32 client_seq = bpf_ntohl(tcp->seq);
    __u32 cookie = cookie_make(tuple, client_seq);

    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->seq = bpf_htonl(cookie);
    tcp->ack = 1;

    __u16 tp = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tp;

    __u32 ti = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = ti;

    struct ethhdr tmp = *ether;
    memcpy(ether->h_dest, tmp.h_source, ETH_ALEN);
    memcpy(ether->h_source, tmp.h_dest, ETH_ALEN);

    ip->check = 0;
    ip->check = carry(sum16(ip, ip_len, data_end));

    __u32 tcp_csum = 0;
    tcp_csum += sum16_32(ip->saddr);
    tcp_csum += sum16_32(ip->daddr);
    tcp_csum += 0x0600;
    tcp_csum += tcp_len << 8;
    tcp->check = 0;
    tcp_csum += sum16(tcp, tcp_len, data_end);
    tcp->check = carry(tcp_csum);

    LOG("SYN cookie sent %x", ip->daddr);
    return XDP_TX;
}

INTERNAL int process_tcp_ack(struct Packet *packet) {
    struct iphdr *ip = packet->ip;
    struct tcphdr *tcp = packet->tcp;

    struct FourTuple tuple = {
        ip->saddr,
        ip->daddr,
        tcp->source,
        tcp->dest
    };

    __u32 client_seq = bpf_ntohl(tcp->seq) - 1;
    __u32 ack_seq = bpf_ntohl(tcp->ack_seq) - 1;

    if (!cookie_check(tuple, client_seq, ack_seq)) {
        LOG("COOKIE FAIL %x", ip->saddr);
        return XDP_DROP;
    }

    LOG("COOKIE OK %x", ip->saddr);
    return XDP_PASS;
}

INTERNAL int process_tcp(struct Packet *packet) {
    struct tcphdr *tcp = packet->tcp;
    __u16 flags = bpf_ntohs(tcp->flags) & (TH_SYN | TH_ACK);

    if (flags == TH_SYN)
        return process_tcp_syn(packet);
    if (flags == TH_ACK)
        return process_tcp_ack(packet);

    return XDP_PASS;
}

INTERNAL int process_ip(struct Packet *packet) {
    struct iphdr *ip = packet->ip;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > (void *)packet->ctx->data_end)
        return XDP_DROP;

    packet->tcp = tcp;
    return process_tcp(packet);
}

INTERNAL int process_ether(struct Packet *packet) {
    struct ethhdr *ether = packet->ether;
    if (ether->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(ether + 1);
    if ((void *)(ip + 1) > (void *)packet->ctx->data_end)
        return XDP_DROP;

    packet->ip = ip;
    return process_ip(packet);
}

SEC("prog")
int xdp_main(struct xdp_md *ctx) {
    struct Packet packet = {};
    packet.ctx = ctx;

    struct ethhdr *ether = (struct ethhdr *)(void *)ctx->data;
    if ((void *)(ether + 1) > (void *)ctx->data_end)
        return XDP_PASS;

    packet.ether = ether;
    return process_ether(&packet);
}

char _license[] SEC("license") = "GPL";
