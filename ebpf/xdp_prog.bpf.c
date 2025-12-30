// xdp_prog.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "nat_map.h"

#define ETH_P_IP    0x0800

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); 
} network_ringbuffer SEC(".maps");

SEC("xdp")
int xdp_packet_handler(struct xdp_md *ctx)
{ 
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct interfaceinfo *info = get_interface_info(ctx->ingress_ifindex);
    if (!info) return XDP_PASS; 

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS; 

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    bool is_wan = info->is_wan;

    if (is_wan) 
    {
        // [WAN -> LAN] (Ingress)
        
        if (ip->ihl < 5) return XDP_PASS;
        void *l4_hdr = (void *)ip + (ip->ihl * 4);
        if (l4_hdr > data_end) return XDP_PASS;
        
        __u16 src_port = 0;
        __u16 dst_port = 0;
        
        if (ip->protocol == IPPROTO_TCP) {
             struct tcphdr *tcp = l4_hdr;
             if ((void *)(tcp + 1) > data_end) return XDP_PASS;
             src_port = tcp->source;
             dst_port = tcp->dest;
        } else if (ip->protocol == IPPROTO_UDP) {
             struct udphdr *udp = l4_hdr;
             if ((void *)(udp + 1) > data_end) return XDP_PASS;
             src_port = udp->source;
             dst_port = udp->dest;
        } else if (ip->protocol == IPPROTO_ICMP) {
             struct icmphdr *icmp = l4_hdr;
             if ((void *)(icmp + 1) > data_end) return XDP_PASS;
             src_port = 0; 
             dst_port = icmp->un.echo.id;
        } else {
             return XDP_PASS;
        }

        struct NAT_TABLE_key_by_external key = {};
        key.external_ipv4 = ip->saddr;
        key.external_port = bpf_ntohs(src_port); 
        key.internal_port = bpf_ntohs(dst_port); 
        key.protocol_number = ip->protocol;

        struct NAT_TABLE_value_by_private *nat_entry = bpf_map_lookup_elem(&map_nat_table, &key);
        
        if (nat_entry) {
            if (Set_DNAT(eth, ip, nat_entry, data_end)) {
                return bpf_redirect(nat_entry->private_ifindex, 0);
            }
        }
    } 
    else 
    {
        // [LAN -> WAN] (Egress)
        
        struct interfaceinfo *wan_info = get_wan_info();
        if (!wan_info) return XDP_PASS; 

        // [FIX] 목적지가 내 IP(GW)이면 SNAT하지 말고 커널로 패스하여 응답하게 함
        if (is_local_ip(ip->daddr)) {
            return XDP_PASS;
        }

        // 인터넷으로 가는 트래픽만 SNAT 처리
        if (process_snat_and_update_map(ctx, eth, ip, wan_info, data_end)) {
            return bpf_redirect(wan_info->ifindex, 0);
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";