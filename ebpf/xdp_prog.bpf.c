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
    __u64 pkt_len = (void *)data_end - (void *)data;
    if (pkt_len == 0) return XDP_PASS;  
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    struct interfaceinfo *info = get_interface_info(ctx->ingress_ifindex);
    if (!info) return XDP_PASS; 

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

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

            if (icmp->type == ICMP_ECHO) {
                // Ping 요청 (LAN -> WAN): ID는 Source 식별자
                src_port = icmp->un.echo.id;
                dst_port = 0;
            } else if (icmp->type == ICMP_ECHOREPLY) {
                // Ping 응답 (WAN -> LAN): ID는 Destination 식별자
                src_port = 0;
                dst_port = icmp->un.echo.id;
            } else {
                // 그 외 ICMP 패킷은 NAT 처리하지 않음
                return XDP_PASS;
            }

    } else {
            return XDP_PASS;
    }

    bool is_wan = info->is_wan;

    // To User 링버퍼
    struct Network_event *e = bpf_ringbuf_reserve(&network_ringbuffer, sizeof(*e), 0);
    if (!e) {
        bpf_printk("[DEBUG] failed to reserve ringbuf entry\n");
        return XDP_PASS;
    }
    e->ifindex = ctx->ingress_ifindex;
    e->pkt_len = pkt_len;
    e->version = 4;
    e->protocol = ip->protocol;
    e->is_wan = is_wan;

    __builtin_memcpy(e->macSrc, eth->h_source, 6);
    __builtin_memcpy(e->macDst, eth->h_dest, 6);
    e->ipSrc = (ip->saddr);
    e->ipDst = (ip->daddr);
    e->portSrc = (src_port);
    e->portDst = (dst_port);

    
    // 패킷 버퍼
    // 패킷 버퍼 (verifier-safe)
    __u32 copylen = pkt_len;
    if (copylen > MAX_PKT_SIZE)
        copylen = MAX_PKT_SIZE;

    // CHUNK 단위 복사 (완전 unroll + 정적 인덱스)
    #pragma unroll
    for (int i = 0; i < (MAX_PKT_SIZE / CHUNK_SIZE); i++) {
        int off = i * CHUNK_SIZE;

        if (off >= copylen)
            break;

        if ((void *)((char *)data + off + CHUNK_SIZE) > data_end)
            break;

        __builtin_memcpy(&e->RawPacket[off],
                        (char *)data + off,
                        CHUNK_SIZE);
    }

    // 남은 바이트 복사 (최대 CHUNK_SIZE 미만, 정적 인덱스)
    #pragma unroll
    for (int j = 0; j < CHUNK_SIZE; j++) {
        int off = (MAX_PKT_SIZE / CHUNK_SIZE) * CHUNK_SIZE + j;

        if (off >= copylen)
            break;

        if ((void *)((char *)data + off + 1) > data_end)
            break;

        e->RawPacket[off] = ((char *)data)[off];
    }




    if (is_wan) 
    {
        // [WAN -> LAN] (Ingress)
        
        

        struct NAT_TABLE_key_by_external key = {};
        key.external_ipv4 = ip->saddr;
        key.external_port = bpf_ntohs(src_port); 
        key.internal_port = bpf_ntohs(dst_port); 
        key.protocol_number = ip->protocol;

        struct NAT_TABLE_value_by_private *nat_entry = bpf_map_lookup_elem(&map_nat_table, &key);
        
        if (nat_entry) {

            struct interfaceinfo *lan_info = get_interface_info(nat_entry->private_ifindex);
            if(lan_info)
            {
                if (Set_DNAT(eth, ip, nat_entry, lan_info, data_end)) {

                
                    // NAT 적용 후를 넣는다
                    __builtin_memcpy(e->macSrc, lan_info->mac_addr, 6);
                    __builtin_memcpy(e->macDst, nat_entry->host_mac, 6);

                    e->ipSrc = (ip->saddr);
                    e->ipDst = nat_entry->private_ipv4; 

                    e->portSrc = (src_port);
                    e->portDst = ( nat_entry->private_port);

                    bpf_ringbuf_submit(e, 0);

                    return bpf_redirect(nat_entry->private_ifindex, 0);
                }
            }
        }
    } 
    else 
    {
        // [LAN -> WAN] (Egress)
        
        struct interfaceinfo *wan_info = get_wan_info();
        if (!wan_info){
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS; 
        }

        // [FIX] 목적지가 내 IP(GW)이면 SNAT하지 말고 커널로 패스하여 응답하게 함
        if (is_local_ip(ip->daddr)) {
            bpf_ringbuf_discard(e, 0);
            return XDP_PASS; 
        }

        // 인터넷으로 가는 트래픽만 SNAT 처리
        if (process_snat_and_update_map(ctx, eth, ip, &src_port, &dst_port, wan_info, e, data_end)) {

            bpf_ringbuf_submit(e, 0);

            return bpf_redirect(wan_info->ifindex, 0);
        }

    }

    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";


