// common.h
#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"
#define true 1
#define false 0

#define MAX_PKT_SIZE 1512
#define CHUNK_SIZE 256

// 인터페이스 정보 (IP, MAC, Gateway 등)
struct interfaceinfo
{
    bool is_enable;
    int  ifindex;
    unsigned int ipv4;
    unsigned int subnetmask;
    unsigned char mac_addr[6];
    bool is_wan;

    unsigned int gw_ipv4;
    unsigned char gw_mac_addr[6];

} __attribute__((packed));

// NAT 테이블 Key (외부에서 들어올 때 기준)
struct NAT_TABLE_key_by_external 
{
    unsigned int external_ipv4;     // 외부 서버 IP
    unsigned int external_port;     // 외부 서버 Port
    unsigned int internal_port;     // 내부 호스트 Port (우리는 Source Port를 변조하지 않는다고 가정)
    unsigned int protocol_number;   // TCP(6) or UDP(17)
} __attribute__((packed));

// NAT 테이블 Value (내부로 전달할 때 기준)
struct NAT_TABLE_value_by_private 
{
    unsigned int private_ipv4;      // 내부 호스트 IP
    unsigned int private_port;      // 내부 호스트 Port
    unsigned int protocol_number;
    unsigned int private_ifindex;   // 내부 인터페이스 인덱스
    unsigned char host_mac[6];      // 내부 호스트 MAC 주소
} __attribute__((packed));

// 링버퍼 이벤트 구조체
struct Network_event {
    int ifindex;
    unsigned int pkt_len;
    int version; 
    int protocol;
    char macSrc[18];
    char macDst[18];
    unsigned char ipSrc[40]; 
    unsigned int portSrc;
    unsigned char ipDst[40];
    unsigned int portDst;
    bool is_wan;
    int is_internal_going_to_internet; 

    struct
    {
        unsigned int source_ipv4;
        unsigned int destination_ipv4;
        unsigned short source_port;
        unsigned short destination_port;
    } original;

    unsigned char RawPacket[MAX_PKT_SIZE];
} __attribute__((packed));

#endif