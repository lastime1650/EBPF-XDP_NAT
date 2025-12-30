// nat_map.h
#ifndef NAT_MAP_H
#define NAT_MAP_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "helps.h"

#define ICMP_ECHOREPLY		0
#define ICMP_ECHO		8

// ============================================================
// MAP DEFINITIONS
// ============================================================

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64); 
    __type(key, int); // ifindex
    __type(value, struct interfaceinfo);
} map_interface_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); 
    __type(key, int); 
    __type(value, int); // WAN ifindex
} map_wan_idx SEC(".maps");

// [NEW] 시스템이 소유한 로컬 IP 목록 (O(1) 조회용)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256); 
    __type(key, __u32); // IP Addr (Network Byte Order)
    __type(value, __u8); // Dummy
} map_local_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct NAT_TABLE_key_by_external);
    __type(value, struct NAT_TABLE_value_by_private);
} map_nat_table SEC(".maps");

// ============================================================
// CHECKSUM HELPERS
// ============================================================

static __always_inline void csum_replace2(__u16 *sum, __be16 old_val, __be16 new_val)
{
    __u32 csum = (~*sum) & 0xffff;
    csum += (~old_val) & 0xffff;
    csum += new_val;
    csum = (csum >> 16) + (csum & 0xffff);
    csum = (csum >> 16) + (csum & 0xffff);
    *sum = ~csum;
}

static __always_inline void csum_replace4(__u16 *sum, __be32 old_val, __be32 new_val)
{
    __u32 csum = (~*sum) & 0xffff;
    csum += (~(old_val & 0xffff)) & 0xffff;
    csum += (~(old_val >> 16)) & 0xffff;
    csum += (new_val & 0xffff);
    csum += (new_val >> 16);
    csum = (csum >> 16) + (csum & 0xffff);
    csum = (csum >> 16) + (csum & 0xffff);
    csum = (csum >> 16) + (csum & 0xffff); 
    *sum = ~csum;
}

// ============================================================
// LOOKUP HELPERS
// ============================================================

static __always_inline struct interfaceinfo *get_interface_info(int ifindex) {
    return bpf_map_lookup_elem(&map_interface_info, &ifindex);
}

static __always_inline struct interfaceinfo *get_wan_info() {
    int key = 0;
    int *wan_ifindex_ptr = bpf_map_lookup_elem(&map_wan_idx, &key);
    if (!wan_ifindex_ptr) return NULL;
    int wan_ifindex = *wan_ifindex_ptr;
    if (wan_ifindex == 0) return NULL;
    return bpf_map_lookup_elem(&map_interface_info, &wan_ifindex);
}

// [NEW] 목적지 IP가 이 기계의 IP인지 확인
static __always_inline bool is_local_ip(__u32 ip) {
    __u8 *exists = bpf_map_lookup_elem(&map_local_ips, &ip);
    return exists != NULL;
}

// ============================================================
// NAT LOGIC
// ============================================================

// [DNAT] 외부 -> 내부
static __always_inline bool Set_DNAT(struct ethhdr *eth, struct iphdr* ip, struct NAT_TABLE_value_by_private* nat, void *data_end)
{
    if ((void*)(ip + 1) > data_end) return false;

    __u32 old_daddr = ip->daddr;
    __u32 new_daddr = nat->private_ipv4;

    void *l4_hdr = (void *)ip + (ip->ihl * 4);
    if (l4_hdr > data_end) return false;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return false;
        csum_replace4(&tcp->check, old_daddr, new_daddr);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return false;
        if (udp->check != 0) {
            csum_replace4(&udp->check, old_daddr, new_daddr);
        }
    } 

    csum_replace4((__u16*)&ip->check, old_daddr, new_daddr);
    ip->daddr = new_daddr;

    struct interfaceinfo *lan_info = get_interface_info(nat->private_ifindex);
    if (lan_info) {
        __builtin_memcpy(eth->h_source, lan_info->mac_addr, 6);
        __builtin_memcpy(eth->h_dest, nat->host_mac, 6);
    }

    return true;
}

// [SNAT + Session Create] 내부 -> 외부
static __always_inline bool process_snat_and_update_map(
    struct xdp_md *ctx, 
    struct ethhdr *eth, 
    struct iphdr* ip, 
    struct interfaceinfo *wan_info, 
    void *data_end)
{
    if ((void*)(ip + 1) > data_end) return false;

    if (ip->ihl < 5) return false;

    void *l4_hdr = (void *)ip + (ip->ihl * 4);
    if (l4_hdr > data_end) return false;

    __u16 src_port = 0;
    __u16 dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return false;
        src_port = tcp->source; 
        dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return false;
        src_port = udp->source;
        dst_port = udp->dest;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = l4_hdr;
        if ((void *)(icmp + 1) > data_end) return false;
        if (icmp->type != ICMP_ECHO) return false;
        src_port = icmp->un.echo.id; 
        dst_port = 0; 
    } else {
        return false; 
    }

    struct NAT_TABLE_key_by_external key = {};
    key.external_ipv4 = ip->daddr;       
    key.external_port = bpf_ntohs(dst_port); 
    key.internal_port = bpf_ntohs(src_port); 
    key.protocol_number = ip->protocol;

    struct NAT_TABLE_value_by_private value = {};
    value.private_ipv4 = ip->saddr;
    value.private_port = bpf_ntohs(src_port);
    value.protocol_number = ip->protocol;
    value.private_ifindex = ctx->ingress_ifindex;
    __builtin_memcpy(value.host_mac, eth->h_source, 6); 

    bpf_map_update_elem(&map_nat_table, &key, &value, BPF_ANY);

    __u32 old_saddr = ip->saddr;
    __u32 new_saddr = wan_info->ipv4;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4_hdr;
        if ((void *)(tcp + 1) > data_end) return false; 
        csum_replace4(&tcp->check, old_saddr, new_saddr);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4_hdr;
        if ((void *)(udp + 1) > data_end) return false;
        if (udp->check != 0) csum_replace4(&udp->check, old_saddr, new_saddr);
    }

    csum_replace4((__u16*)&ip->check, old_saddr, new_saddr);
    ip->saddr = new_saddr;

    __builtin_memcpy(eth->h_source, wan_info->mac_addr, 6);
    __builtin_memcpy(eth->h_dest, wan_info->gw_mac_addr, 6);

    return true;
}

#endif