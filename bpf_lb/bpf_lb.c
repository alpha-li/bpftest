#include <stdint.h>
#include <asm/types.h>
#include <linux/bpf.h>
#include <linux/pkt_sched.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "helpers.h"

struct tuple
{
    long packets;
    long bytes;
};

struct Service
{
    __be32 dstIp;
    __be16 dstPort;
    __be16 pad;
};

#define MAX_ENDPOINT_NUM 32

struct Endpoint
{
    __be32 ip;
    __be16 port;
    __be16 pad;
};

struct EndpointSet
{
    uint16_t ep_num;
    uint16_t prev;
    struct Endpoint endpoints[MAX_ENDPOINT_NUM];
};

#define BPF_MAP_ID_STATS 1 /* agent's map identifier */
#define BPF_MAX_RECORD 256
struct bpf_elf_map __section("maps") service_map = {
    .type = BPF_MAP_TYPE_HASH,
    //.id = BPF_MAP_ID_STATS,
    .size_key = sizeof(struct Service),
    .size_value = sizeof(struct EndpointSet),
    .max_elem = BPF_MAX_RECORD,
    //.pinning = PIN_GLOBAL_NS,
};

static inline int match_service(struct __sk_buff *skb, __u64 nh_off);

static void set_tcp_dport(struct __sk_buff *skb, int nh_off,
                          __u16 old_port, __u16 new_port)
{
    bpf_l4_csum_replace(skb, nh_off + sizeof(struct iphdr) + offsetof(struct tcphdr, check),
                        old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, nh_off + sizeof(struct iphdr) + offsetof(struct tcphdr, dest),
                        &new_port, sizeof(new_port), 0);
}

static void set_dest_ip(struct __sk_buff *skb, int nh_off,
                        __u16 old_ip, __u16 new_ip)
{
    bpf_l3_csum_replace(skb, nh_off + offsetof(struct iphdr, daddr),
                        old_ip, new_ip, sizeof(new_ip));
    bpf_skb_store_bytes(skb, nh_off + offsetof(struct iphdr, daddr),
                        &new_ip, sizeof(new_ip), 0);
}

__section("test") int test_main(struct __sk_buff *skb)
{
    return 0;
}

__section("cls_ingress") int cls_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;

    __u16 h_proto;
    __u64 nh_off = 0;
    nh_off = sizeof(*eth);

    if (data + nh_off > data_end)
    {
        return TC_ACT_OK;
    }

    h_proto = eth->h_proto;

    trace_printk("Got Packet!\n");

    if (h_proto == bpf_htons(ETH_P_IP))
     {
         match_service(skb, nh_off);
    //     if (match_service(skb, nh_off) == 1)
    //     {
    //         trace_printk("Yes! Hit Service!\n");
    //     }
     }

    return TC_ACT_OK;
}

// void get_endpoint(struct EndpointSet *eps, struct Endpoint *ep)
// {
//     if(eps == 0|| ep == 0|| eps->ep_num == 0||eps->ep_num >= MAX_ENDPOINT_NUM) return;
//     eps->prev = (eps->prev + 1) % (eps->ep_num);
//     *ep = eps->endpoints[eps->prev];
// }

static inline  int match_service(struct __sk_buff *skb, __u64 nh_off)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct iphdr *iph = data + nh_off;

    if (iph + 1 > data_end)
    {
        return 0;
    }

    if (iph->protocol != IPPROTO_TCP)
    {
        return 0;
    }

    __u32 tcp_hlen = 0;
    __u32 ip_hlen = 0;
    __u32 poffset = 0;
    __u32 plength = 0;
    __u32 ip_total_length = iph->tot_len;

    ip_hlen = iph->ihl << 2;

    if (ip_hlen < sizeof(*iph))
    {
        return 0;
    }

    struct tcphdr *tcph = data + nh_off + sizeof(*iph);

    if (tcph + 1 > data_end)
    {
        return 0;
    }

    struct Service service;

    service.dstIp = iph->daddr;
    service.dstPort = tcph->dest;
    service.pad = 0; //all the fields must be assigned, or verified failed

    struct Endpoint ep;

    trace_printk("Got packet! ip:%u port:%u\n", bpf_ntohl(iph->daddr), bpf_ntohs(tcph->dest));
    uint32_t a = 10;

    struct EndpointSet *eps = bpf_map_lookup_elem(&service_map, &service);
    if (eps == 0 || eps->ep_num == 0)
    {
        trace_printk("No Endpoint\n");
        return 0;
    }

    //get_endpoint(eps, &ep);
    

    // set_tcp_dport(skb, nh_off, tcph->dest, ep.port);
    // set_dest_ip(skb, nh_off, iph->daddr, ep.ip);

    // return 1;
    return 1;
}

char __license[] __section("license") = "GPL";