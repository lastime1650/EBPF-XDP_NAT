/*#include <fstream>
#include <sstream>
#include <iostream>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <thread>
#include <vector>
#include <set>
#include <string>
#include <ifaddrs.h>
#include <memory>
#include <optional>

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ebpf/xdp_prog.skel.h"
}


#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <cstring>
#include <vector>
#include <optional>
#include <string>
#include <map>

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <unistd.h>

class Forwarder
{
enum interface_type
{
    INTERFACE_TYPE_UNKNOWN,
    
    WAN,
    LAN,
    lo
};
enum interface_ip_allocate_type
{
    IP_ALLOC_UNKNOWN,

    STATIC,
    DYNAMIC
};

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
struct interface_information
{
    interface_type type;
    interface_ip_allocate_type ip_alloc_type;

    std::optional<std::string> mac;
    std::optional<std::string> ipv4;
    std::optional<std::string> ipv6;

    std::optional<std::string> subnetmask;

    std::optional<std::string> gw_ip;
    std::optional<std::string> gw_mac;

    interfaceinfo for_xdp_map_value;
};


struct NAT_TABLE_key_by_external // key
{
    unsigned int external_ipv4;
    unsigned int      external_port; // 유효하지 않으면 기본값 0
    unsigned int      internal_port; // 유효하지 않으면 기본값 0 (외부 -> 내부시, 요청했던 내부호스트의 소스포트)
    unsigned int       protocol_number;

    bool operator<(const NAT_TABLE_key_by_external &other) const {
        if (external_ipv4 != other.external_ipv4) return external_ipv4 < other.external_ipv4;
        if (external_port != other.external_port) return external_port < other.external_port;
        if (internal_port != other.internal_port) return internal_port < other.internal_port;
        return protocol_number < other.protocol_number;
    }

} __attribute__((packed));

struct NAT_TABLE_value_by_private // value
{
    unsigned int private_ipv4;
    unsigned int      private_port;    // destination port을 이값으로
    unsigned int       protocol_number;
    unsigned int        private_ifindex; // 이쪽으로 패킷 이동

    unsigned char host_mac[6]; // private_ipv4 의 맥주소
} __attribute__((packed));


struct NAT_Table
{
    
    NAT_TABLE_key_by_external external;
    NAT_TABLE_value_by_private internal;

    bool Set_NAT(
        
        const unsigned int& internal_private_ifindex,
        const unsigned char protocol_number,

        const unsigned int& internal_private_source_ip,
        const unsigned short& internal_private_source_port,
        const unsigned int& external_global_destination_ip, // NAT Key가 될 외부 IP (WAN IP)
        const unsigned short& external_global_destination_port, // NAT Key가 될 외부 Port

        const unsigned char* internal_private_host_mac
    ){
        memset(&external, 0, sizeof(external));
        memset(&internal, 0, sizeof(internal));

        external.external_ipv4 = external_global_destination_ip;
        external.external_port = external_global_destination_port;
        
        external.protocol_number = protocol_number;




        internal.private_ipv4 = internal_private_source_ip;
        internal.private_port = internal_private_source_port;

        internal.protocol_number = protocol_number;
        internal.private_ifindex = internal_private_ifindex; // 내부망 인터페이스 인덱스

        memcpy( internal.host_mac, internal_private_host_mac, sizeof(internal.host_mac) );

        external.internal_port = internal.private_port;

        return true;
    }

};
    std::thread LoopArpGetThread;
public:
    Forwarder()
    {
        LoopArpGetThread = std::thread( [this](){ _____loop_update_arp_table_map(); } );
        interface_infos = __load_interfaces();
    }

    // 내부망에서 외부망으로 갈때 호출해야한다.
    bool Add_Table(

        const unsigned int& internal_private_ifindex,
        const unsigned char protocol_number,

        const unsigned int& internal_private_source_ip,
        const unsigned short& internal_private_source_port,
        const unsigned int& external_global_destination_ip, // NAT Key가 될 외부 IP (WAN IP)
        const unsigned short& external_global_destination_port // NAT Key가 될 외부 Port
    ){
        if( !ARPTABLES.count(internal_private_source_ip) )
            return false;
        std::cout << "ARPTABLES[" << internal_private_source_ip << "] MAC: " << ARPTABLES[internal_private_source_ip].mac << std::endl;
        // 1. NAT Entry 데이터 준비 (Big Endian 변환 포함)
        NAT_Table entry;
        bool success = entry.Set_NAT(
            internal_private_ifindex,
            protocol_number,
            internal_private_source_ip,
            internal_private_source_port,
            external_global_destination_ip,
            external_global_destination_port,
            ARPTABLES[internal_private_source_ip].original.mac
        );
        if (!success) {
            std::cerr << "\033[1;31m[ERROR] Failed to parse NAT entry IPs.\033[0m" << std::endl;
            return false;
        }

        // 2. 가시화된 디버그 출력 (ANSI Color 사용)
        std::string proto_str = (protocol_number == IPPROTO_TCP) ? "TCP" :
                                (protocol_number == IPPROTO_UDP) ? "UDP" : 
                                std::to_string(protocol_number);

        std::cout << "\n\033[1;32m[NAT TABLE UPDATE]\033[0m ============================================" << std::endl;
        std::cout << " \033[1;36mProtocol   :\033[0m " << proto_str << " (" << (int)protocol_number << ")" << std::endl;
        
        // Key (외부에서 들어올 때의 주소)
        std::cout << " \033[1;35m[KEY] Ext  :\033[0m " << external_global_destination_ip 
                  << ":" << external_global_destination_port << std::endl;

        std::cout << "      \033[1;33m|\033[0m (Maps to)" << std::endl;
        std::cout << "      \033[1;33mv\033[0m" << std::endl;

        // Value (내부로 전달될 실제 주소)
        std::cout << " \033[1;35m[VAL] Int  :\033[0m " << internal_private_source_ip 
                  << ":" << internal_private_source_port 
                  << " \033[90m(IfIndex: " << internal_private_ifindex << ")\033[0m" << std::endl;
        std::cout << " ===============================================================\n" << std::endl;

        for( auto&[ifindex, NAT] : TABLE_MAP_by_ifindex )
        {
            if( NAT.tables.find(entry.external) !=  NAT.tables.end() )
            {
                // 시간 업데이트
            }
            else
            {
                // BPF_ANY: 키가 없으면 생성, 있으면 갱신(LRU 최신화)
                int ret = bpf_map_update_elem(
                    NAT.map_fd, 
                    &entry.external, // Key
                    &entry.internal, // Value
                    BPF_ANY
                );

                if (ret != 0) {
                    // 실패 시 에러 출력 (perror는 errno를 기반으로 메시지 출력)
                    std::cerr << "\033[1;31m"; // Red
                    perror("bpf_map_update_elem failed");
                    std::cerr << "\033[0m"; // Reset
                    return false;
                }

                NAT.tables[entry.external] = entry.internal; // NAT 등록
            }
        }

        std::cout << "\n\033[1;32m[NAT TABLE UPDATED]\033" << std::endl;
        
        return true;
    }

    // 내부망에서 외부망으로 갈때 호출해야한다.
    // 기존 테이블의 타임아웃 시간을 증가
    //bool Time_Update_Table(){}

    bool Is_LAN(const int& ifindex)
    {
        if( interface_infos[ifindex].type == interface_type::LAN )
            return true;
        else
            return false;
    }
    bool Is_WAN(const int& ifindex)
    {
        if( interface_infos[ifindex].type == interface_type::WAN )
            return true;
        else
            return false;
    }
    int Get_WAN_interface()
    {
        for(auto&[ifindex, info ]: interface_infos)
        {
            if( Is_WAN(ifindex) )
                return ifindex;
        }
        
        return -1;
    }

    // output: ifindex 
    int Is_Contain_Interface_in_System(const std::string& ipv4)
    {
        return  _FindInterfaceForIp(ipv4);
    }

    // add MAP_INTERFACE_INFO map_fd
    bool Add__map_interface_info__map_fd(int map_fd)
    {
        if( map_interface_info__map_fds.count(map_fd) )
            return false; // 중복
        map_interface_info__map_fds.insert(map_fd);
        
        for (auto & [ifindex, info] : interface_infos) {
            std::cout << "ifindex: " << ifindex << "subnetmask" << info.for_xdp_map_value.subnetmask << "ipv4" << info.for_xdp_map_value.ipv4 << std::endl;
            if (bpf_map_update_elem(map_fd, &ifindex, &info.for_xdp_map_value, BPF_ANY) != 0) {
                perror("bpf_map_update_elem");
                return false;
            }
        }
        return true;
    }

    // add MAP_NAT_TABLE map_fd
    bool Add__map_nat_table__map_fd(int map_fd, int ifindex)
    {
        if ( Is_WAN(ifindex) )
        {
            TABLE_MAP_by_ifindex[ifindex].map_fd = map_fd;
        }
        return true;
    }

private:
    struct TABLE_MAP_by_IFINDEX
    {
        std::map<NAT_TABLE_key_by_external, NAT_TABLE_value_by_private> tables;
        int map_fd ;
    };
    std::map<int, TABLE_MAP_by_IFINDEX > TABLE_MAP_by_ifindex;

    std::set<int> map_interface_info__map_fds;

    std::map<int, interface_information> interface_infos;


    std::map<int, interface_information> __load_interfaces()
    {
        std::map<int, interface_information> output;

        auto gateways = ___getGateways();

        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1)
        {
            perror("getifaddrs");
            return output;
        }

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr)
                continue;
            
            std::string if_name(ifa->ifa_name);
            if ( if_name.empty() )
                continue;

            int ifindex = (int)if_nametoindex(ifa->ifa_name);
            if ( ifindex <= 0)
                continue;

            // 참조로 업데이트해야함. 동일 인터페이스에 다양한 family 로 가져오기 때문. *****************
            interface_information &target_info = output[ifindex];

            // 기본 정보 설정 (ifindex가 0이면 아직 초기화 안 된 것으로 간주)
            // 매번 덮어써도 상관없는 플래그나 인덱스는 그냥 업데이트합니다.
            target_info.for_xdp_map_value.ifindex = ifindex;
            target_info.for_xdp_map_value.is_enable = ifa->ifa_flags & IFF_UP;

            // 타입 결정 로직 (매번 수행해도 무방하거나, 초기화 체크 후 수행)
            if (if_name == "lo") {
                target_info.type = lo;
            }
            else {
                if (gateways.empty())
                {
                    target_info.type = interface_type::INTERFACE_TYPE_UNKNOWN;
                }

                for(auto& gateway_ : gateways)
                {
                    if(  gateway_.interface == if_name ) {
                        target_info.type = WAN;
                        target_info.for_xdp_map_value.is_wan = true;
                    } else {
                        target_info.type = LAN;
                        target_info.for_xdp_map_value.is_wan = false;
                    }
                }

                
            }
            // IP 할당 타입 기본값
            if (target_info.ip_alloc_type == IP_ALLOC_UNKNOWN) {
                 target_info.ip_alloc_type = interface_ip_allocate_type::IP_ALLOC_UNKNOWN;
            }

            // 각 프로토콜 패밀리에 따라 해당 필드만 업데이트합니다.
            if (ifa->ifa_addr->sa_family == AF_INET) // IPv4
            {
                char ip[INET_ADDRSTRLEN];
                char netmask[INET_ADDRSTRLEN];

                inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr, netmask, INET_ADDRSTRLEN);

                target_info.ipv4 = ip;
                target_info.subnetmask = netmask;

                // XDP용 구조체 필드만 갱신 (다른 필드는 건드리지 않음)
                target_info.for_xdp_map_value.ipv4 = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
                target_info.for_xdp_map_value.subnetmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;

                
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6) // IPv6
            {
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, ip, INET6_ADDRSTRLEN);
                target_info.ipv6 = ip;
                // IPv6 관련 XDP 필드가 있다면 여기서 업데이트
            }
            else if (ifa->ifa_addr->sa_family == AF_PACKET) // MAC
            {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                char mac[18];
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         (int)s->sll_addr[0], (int)s->sll_addr[1], (int)s->sll_addr[2],
                         (int)s->sll_addr[3], (int)s->sll_addr[4], (int)s->sll_addr[5]);
                target_info.mac = mac;

                memcpy(target_info.for_xdp_map_value.mac_addr, s->sll_addr, 6);
                // 여기서 for_xdp_map_value의 ipv4를 건드리지 않는 것이 핵심
            }


            

            target_info.for_xdp_map_value.gw_ipv4 = 0;
            memset( &target_info.for_xdp_map_value.gw_mac_addr, 0, sizeof(target_info.for_xdp_map_value.gw_mac_addr) );
            for(auto& gateway_ : gateways)
            {
                target_info.gw_ip = gateway_.gw_ip;
                target_info.gw_mac = gateway_.gw_mac;

                target_info.for_xdp_map_value.gw_ipv4 =gateway_.original.gw_ip;
                memcpy(& target_info.for_xdp_map_value.gw_mac_addr,&gateway_.original.gw_mac, sizeof(gateway_.original.gw_mac) );
            }
            
        }

        freeifaddrs(ifaddr);

        // 디버깅 출력
        for(auto&[idx, info] : output)
        {
            std::cout << "Idx: " << idx 
                      << " Name: " << (info.type == WAN ? "WAN" : "LAN")
                      << " IPv4: " << (info.ipv4.has_value() ? info.ipv4.value() : "None") 
                      << "GW_IP: " << (info.gw_ip.has_value() ? info.gw_ip.value() : "None") 
                      << "GW_MAC: " << (info.gw_mac.has_value() ? info.gw_mac.value() : "None") 
                      << " MaskHex: " << std::hex << info.for_xdp_map_value.subnetmask << std::dec
                      << std::endl;
        }

        return output;
    }

    // 포함하는 IP인가?
    int _FindInterfaceForIp(const std::string &ip) 
    {
        struct in_addr target_addr;
        if (inet_pton(AF_INET, ip.c_str(), &target_addr) != 1) {
            std::cerr << "Invalid IP format: " << ip << std::endl;
            return -1;
        }

        for (const auto& [ifindex, info] : interface_infos) 
        {
            if( info.type == interface_type::lo || info.type == interface_type::INTERFACE_TYPE_UNKNOWN)
                continue;

            if (!info.ipv4.has_value() || !info.subnetmask.has_value())
                continue;

            struct in_addr iface_addr, mask_addr;
            inet_pton(AF_INET, info.ipv4->c_str(), &iface_addr);
            inet_pton(AF_INET, info.subnetmask->c_str(), &mask_addr);

            if ((target_addr.s_addr & mask_addr.s_addr) == (iface_addr.s_addr & mask_addr.s_addr)) {
                return ifindex;
            }
        }

        return -1; // 어느 네트워크에도 속하지 않음
    }

    // 게이트웨이 정보 수집
    struct GW_INFO
    {
        std::string interface;

        std::string gw_ip;
        std::string gw_mac;

        struct
        {
            unsigned  int gw_ip;
            u_char gw_mac[6];
        }original;
    };
    std::vector<GW_INFO> ___getGateways() {
        std::vector<GW_INFO> gateways;
        std::ifstream routeFile("/proc/net/route");
        if (!routeFile.is_open()) return gateways;

        std::string line;
        std::getline(routeFile, line); // Header skip

        while (std::getline(routeFile, line)) {
            std::stringstream ss(line);
            std::string iface, dest, gateway;
            ss >> iface >> dest >> gateway;

            if (dest == "00000000") {
                

                auto gateway_ =  GW_INFO{ .interface = iface, .gw_ip = ____hexToIp(gateway) };

                struct in_addr iface_addr;
                inet_pton(AF_INET, gateway_.gw_ip.c_str(), &iface_addr);
                gateway_.original.gw_ip = iface_addr.s_addr;

                
                _____get_mac_ioctl(gateway_.gw_ip.c_str(), iface.c_str(), gateway_.original.gw_mac);
                char buf[18];
                snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                         gateway_.original.gw_mac[0],  gateway_.original.gw_mac[1],  gateway_.original.gw_mac[2],  gateway_.original.gw_mac[3],  gateway_.original.gw_mac[4],  gateway_.original.gw_mac[5]);
                gateway_.gw_mac = std::string(buf);

                gateways.push_back ( gateway_ );

            }

            
        }

        return gateways;
    }

    int _____get_mac_ioctl(const char *ip_str, const char *ifname, unsigned char mac[6]) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return -1;

        struct arpreq req;
        memset(&req, 0, sizeof(req));
        struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
        sin->sin_family = AF_INET;
        inet_pton(AF_INET, ip_str, &sin->sin_addr);

        strncpy(req.arp_dev, ifname, IFNAMSIZ-1);

        if (ioctl(fd, SIOCGARP, &req) == -1) {
            close(fd);
            return -1;
        }

        memcpy(mac, req.arp_ha.sa_data, 6);
        close(fd);
        return 0;
    }

    std::string ____hexToIp(const std::string& hex) {
        if (hex.length() != 8) return "0.0.0.0";
        unsigned int addr;
        std::stringstream ss;
        ss << std::hex << hex;
        ss >> addr;

        struct in_addr in;
        in.s_addr = addr;
        return std::string(inet_ntoa(in));
    }

    bool ____get_interface_mac(const std::string &ifname, unsigned char mac[6]) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return false;

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ-1);

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
            close(fd);
            return false;
        }

        for (int i = 0; i < 6; i++)
            mac[i] = (unsigned char)ifr.ifr_hwaddr.sa_data[i];

        close(fd);
        return true;
    }

    void _____loop_update_arp_table_map()
    {
        for( auto& table : ___GetArpTable())
        {
            ARPTABLES[table.original.ipv4] = table;
        }
        
        while(1)
        {
            if( !interface_infos.empty() )
            {
                std::vector<std::thread> threads_;
                for( auto&[ifindex, info] : interface_infos)
                {
                    threads_.push_back(
                        std::thread(
                            [this, ifindex, info]()
                            {
                                if( info.ipv4.has_value() && info.subnetmask.has_value() )
                                    ScanSubnetWithICMP(info.ipv4.value(), info.subnetmask.value());
                            }
                        )
                    );
                }
                for(auto&t : threads_)
                {
                    if(t.joinable())
                        t.join();
                }

                for( auto& table : ___GetArpTable())
                {
                    ARPTABLES[table.original.ipv4] = table;
                }
                
            }

            sleep(2);
            
        }
    }
    void ScanSubnetWithICMP(
        const std::string& ipStr,
        const std::string& netmaskStr
    ) {
        in_addr ip{}, netmask{};
        inet_pton(AF_INET, ipStr.c_str(), &ip);
        inet_pton(AF_INET, netmaskStr.c_str(), &netmask);

        uint32_t ip_u = ntohl(ip.s_addr);
        uint32_t mask_u = ntohl(netmask.s_addr);

        uint32_t network = ip_u & mask_u;
        uint32_t broadcast = network | (~mask_u);

        std::vector<std::string> hostIPs;

        for (uint32_t host = network + 1; host < broadcast; ++host) {
            in_addr addr{};
            addr.s_addr = htonl(host);

            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            hostIPs.emplace_back(buf);
        }

        for (const auto& targetIP : hostIPs) {
            std::string cmd =
                "ping -c 1 -I " + targetIP + " > /dev/null 2>&1";
            system(cmd.c_str());
        }
    }

    struct ArpEntry {
        std::string ipv4;
        std::string mac;

        struct
        {
            unsigned int ipv4;
            unsigned char mac[6];
        }original;
    };
    std::map<unsigned int, ArpEntry> ARPTABLES;
    std::vector<ArpEntry> ___GetArpTable()
    {
        std::vector<ArpEntry> result;
        std::ifstream file("/proc/net/arp");
        std::string line;

        // 헤더 스킵
        std::getline(file, line);

        while (std::getline(file, line)) {
            std::istringstream iss(line);

            std::string ip, hwType, flags, macStr, mask, device;
            iss >> ip >> hwType >> flags >> macStr >> mask >> device;

            if (macStr == "00:00:00:00:00:00")
                continue;

            ArpEntry entry;
            entry.ipv4 = ip;
            entry.mac = macStr;

            // IPv4 문자열 → uint32_t
            inet_pton(AF_INET, ip.c_str(), &entry.original.ipv4);

            // MAC 문자열 → 6바이트
            unsigned int macBytes[6];
            std::sscanf(
                macStr.c_str(),
                "%x:%x:%x:%x:%x:%x",
                &macBytes[0], &macBytes[1], &macBytes[2],
                &macBytes[3], &macBytes[4], &macBytes[5]
            );

            for (int i = 0; i < 6; ++i) {
                entry.original.mac[i] = static_cast<unsigned char>(macBytes[i]);
            }

            result.push_back(entry);
        }

        return result;
    }

};




static bool running = true;

#define MAX_PKT_SIZE 9216
struct Network_event {
    int ifindex;
    unsigned int pkt_len;
    
    // IP 버전 (4 또는 6)
    int version; 
    
    // L4 프로토콜 (TCP=6, UDP=17)
    int protocol;

    // MAC 주소 (읽을 수 있는 형태크기)
    char macSrc[18];
    char macDst[18];

    // IPv4는 4바이트, IPv6는 읽을 수 있는
    unsigned char ipSrc[40]; 
    unsigned int portSrc;

    unsigned char ipDst[40];
    unsigned int portDst;

    bool is_wan;                        // 핸들러에 들어온 인터페이스는 WAN인가? ( (true)외부 -> 내부 / (false)내부 -> 외부 )
    int is_internal_going_to_internet;     // 내부망에서 인터넷으로 가는 것인가? 

    struct
    {
        unsigned int source_ipv4;
        unsigned int destination_ipv4;
        unsigned short source_port;
        unsigned short destination_port;
    }original;

    unsigned char RawPacket[MAX_PKT_SIZE];
} __attribute__((packed));

// ring buffer callback 
static int handle_event(void *ctx, void *data, size_t len)
{
    Forwarder *forwarder = (Forwarder*)ctx;
    const struct Network_event *e = (const struct Network_event *)data;

    // 방향 확인
    if ( e->is_wan )
    {
        // 외부 -> 내부
    }else
    {
        // 내부 -> 외부
        
        if( e->is_internal_going_to_internet )
        {
            // 인터넷으로 가는경우 Catch
           
            forwarder->Add_Table( // Table 조회하면서, 없으면 추가 생성하는 메서드 호출 
                e->ifindex,
                e->protocol,
                e->original.source_ipv4,
                e->original.source_port,
                e->original.destination_ipv4,
                e->original.destination_port
            );

        }
    }


    return 0;
}

static void sigint(int)
{
    running = false;
}
#include <linux/if_link.h> // XDP_FLAGS_SKB_MODE 정의
int main()
{

    Forwarder forward;



    struct ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    std::set<std::string> seen_ifnames;
    std::vector<int> ifindices;

    // 인터페이스 추출
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_name || strcmp(ifa->ifa_name, "lo") == 0)
            continue;

        std::string ifname(ifa->ifa_name);
        if (seen_ifnames.count(ifname))
            continue;

        unsigned int ifindex = if_nametoindex(ifa->ifa_name);
        if (ifindex == 0)
            continue;

        seen_ifnames.insert(ifname);
        ifindices.push_back(ifindex);
    }
    freeifaddrs(ifaddr);

    signal(SIGINT, sigint);

    // 각 인터페이스마다 XDP attach + ring buffer thread
    std::vector<std::thread> Threads;
    for (int ifindex : ifindices)
    {
        Threads.emplace_back([ifindex, &forward]() { 
            struct xdp_prog_bpf *skel = xdp_prog_bpf__open_and_load();
            if (!skel) {
                std::cerr << "failed to open/load skeleton\n";
                return;
            }

            int map_interface_fd = bpf_map__fd(skel->maps.map_interface_info);
            forward.Add__map_interface_info__map_fd(map_interface_fd);

            int map_nat_table_fd = bpf_map__fd(skel->maps.map_nat_table);
            forward.Add__map_nat_table__map_fd(map_nat_table_fd, ifindex);

            int prog_fd = bpf_program__fd(skel->progs.xdp_packet_handler);
            int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, nullptr);
            //struct bpf_link *link = bpf_program__attach_xdp(
            //    skel->progs.xdp_packet_handler, ifindex);
            //if (!link) {
            //    std::cerr << "failed to attach xdp\n";
            //    xdp_prog_bpf__destroy(skel);
            //    return;
            //}

            struct ring_buffer *rb = ring_buffer__new(
                bpf_map__fd(skel->maps.network_ringbuffer),
                handle_event,
                (void*)&forward,
                nullptr
            );

            if (!rb) {
                std::cerr << "failed to create ring buffer\n";
                //bpf_link__destroy(link);
                xdp_prog_bpf__destroy(skel);
                return;
            }

            while (running)
                ring_buffer__poll(rb, 1 timeout ms );

            ring_buffer__free(rb);
            //bpf_link__destroy(link);
            xdp_prog_bpf__destroy(skel);
        });
    }

    for (auto &t : Threads)
        if (t.joinable())
            t.join();

    return 0;
}
*/

// C++ Standard Library
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <memory>
#include <optional>
#include <algorithm>
#include <csignal>

// C Standard Library
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <unistd.h>

// System / Network Headers
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>

// eBPF / libbpf
extern "C" {
    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>
    #include "ebpf/xdp_prog.skel.h"
}


#define MAX_PKT_SIZE 1512
typedef __u8 bool_t; 

struct interfaceinfo {
    bool_t is_enable;
    int  ifindex;
    unsigned int ipv4;       
    unsigned int subnetmask; 
    unsigned char mac_addr[6];
    bool_t is_wan;
    unsigned int gw_ipv4;    
    unsigned char gw_mac_addr[6];
} __attribute__((packed));

struct NAT_TABLE_key_by_external {
    unsigned int external_ipv4;
    unsigned int external_port;
    unsigned int internal_port;
    unsigned int protocol_number;
    bool operator<(const NAT_TABLE_key_by_external &other) const {
        if (external_ipv4 != other.external_ipv4) return external_ipv4 < other.external_ipv4;
        if (external_port != other.external_port) return external_port < other.external_port;
        if (internal_port != other.internal_port) return internal_port < other.internal_port;
        return protocol_number < other.protocol_number;
    }
} __attribute__((packed));

struct NAT_TABLE_value_by_private {
    unsigned int private_ipv4;
    unsigned int private_port;
    unsigned int protocol_number;
    unsigned int private_ifindex;
    unsigned char host_mac[6];
} __attribute__((packed));

struct Network_event {
    int ifindex;
    unsigned int pkt_len;
    int version;
    int protocol;
    unsigned char macSrc[6];
    unsigned char macDst[6];
    unsigned int ipSrc;
    unsigned int portSrc;
    unsigned int ipDst;
    unsigned int portDst;
    bool is_wan;
    int is_internal_going_to_internet;

    unsigned char RawPacket[MAX_PKT_SIZE];
} __attribute__((packed));

class Forwarder {
public:
    enum interface_type { UNKNOWN, WAN, LAN, lo };
    struct interface_information {
        interface_type type;
        interfaceinfo for_xdp_map_value;
    };

private:
    std::map<int, interface_information> interface_infos;
    int map_interface_fd = -1;
    int map_wan_idx_fd = -1;
    int map_local_ips_fd = -1; // [NEW]

public:
    Forwarder() {
        interface_infos = __load_interfaces();
    }

    void SetMapFDs(int interface_fd, int wan_idx_fd, int local_ips_fd) {
        map_interface_fd = interface_fd;
        map_wan_idx_fd = wan_idx_fd;
        map_local_ips_fd = local_ips_fd;
    }

    bool PopulateMaps() {
        if (map_interface_fd < 0 || map_wan_idx_fd < 0 || map_local_ips_fd < 0) return false;

        for (auto & [ifindex, info] : interface_infos) {
            // 1. Interface Info Map
            if (bpf_map_update_elem(map_interface_fd, &ifindex, &info.for_xdp_map_value, BPF_ANY) != 0) {
                perror("bpf_map_update_elem(interface)");
                return false;
            }

            // 2. Local IPs Map (For avoiding Self-SNAT)
            if (info.for_xdp_map_value.ipv4 != 0) {
                __u32 ip = info.for_xdp_map_value.ipv4;
                __u8 dummy = 1;
                if (bpf_map_update_elem(map_local_ips_fd, &ip, &dummy, BPF_ANY) != 0) {
                    perror("bpf_map_update_elem(local_ips)");
                    return false;
                }
                char buf[INET_ADDRSTRLEN];
                struct in_addr ia; ia.s_addr = ip;
                std::cout << "[INIT] Registered Local IP: " << inet_ntop(AF_INET, &ia, buf, INET_ADDRSTRLEN) << std::endl;
            }

            // 3. WAN Index Map
            if (info.type == WAN) {
                int key = 0;
                int wan_idx = ifindex;
                std::cout << "[INIT] Setting WAN Index to: " << wan_idx << std::endl;
                if (bpf_map_update_elem(map_wan_idx_fd, &key, &wan_idx, BPF_ANY) != 0) {
                    perror("bpf_map_update_elem(wan_idx)");
                    return false;
                }
            }
        }
        return true;
    }

private:
    struct GW_INFO {
        std::string interface;
        unsigned int gw_ip;
        unsigned char gw_mac[6];
    };

    std::map<int, interface_information> __load_interfaces() {
        std::map<int, interface_information> output;
        auto gateways = ___getGateways();
        struct ifaddrs *ifaddr, *ifa;

        if (getifaddrs(&ifaddr) == -1) return output;

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr || !ifa->ifa_name) continue;
            
            int ifindex = (int)if_nametoindex(ifa->ifa_name);
            if (ifindex <= 0) continue;

            interface_information &target_info = output[ifindex];
            target_info.for_xdp_map_value.ifindex = ifindex;
            target_info.for_xdp_map_value.is_enable = (ifa->ifa_flags & IFF_UP);
            
            std::string ifname(ifa->ifa_name);
            if (ifname == "lo") target_info.type = lo;
            else {
                target_info.type = LAN;
                target_info.for_xdp_map_value.is_wan = 0;
                for(auto& gw : gateways) {
                    if(gw.interface == ifname) {
                        target_info.type = WAN;
                        target_info.for_xdp_map_value.is_wan = 1;
                        break;
                    }
                }
            }

            if (ifa->ifa_addr->sa_family == AF_INET) {
                target_info.for_xdp_map_value.ipv4 = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
                target_info.for_xdp_map_value.subnetmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
            } else if (ifa->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
                memcpy(target_info.for_xdp_map_value.mac_addr, s->sll_addr, 6);
            }

            target_info.for_xdp_map_value.gw_ipv4 = 0;
            memset(target_info.for_xdp_map_value.gw_mac_addr, 0, 6);
            for(auto& gw : gateways) {
                if(gw.interface == ifname) {
                    target_info.for_xdp_map_value.gw_ipv4 = gw.gw_ip;
                    memcpy(target_info.for_xdp_map_value.gw_mac_addr, gw.gw_mac, 6);
                }
            }
        }
        freeifaddrs(ifaddr);
        return output;
    }

    std::vector<GW_INFO> ___getGateways() {
        std::vector<GW_INFO> gateways;
        std::ifstream routeFile("/proc/net/route");
        std::string line;
        std::getline(routeFile, line); 

        while (std::getline(routeFile, line)) {
            std::stringstream ss(line);
            std::string iface, dest, gateway;
            ss >> iface >> dest >> gateway;

            if (dest == "00000000") {
                GW_INFO gw_info;
                gw_info.interface = iface;
                unsigned int addr;
                std::stringstream sshex; sshex << std::hex << gateway; sshex >> addr;
                struct in_addr in; in.s_addr = addr;
                gw_info.gw_ip = in.s_addr;

                int fd = socket(AF_INET, SOCK_DGRAM, 0);
                if (fd >= 0) {
                    struct arpreq req;
                    memset(&req, 0, sizeof(req));
                    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
                    sin->sin_family = AF_INET;
                    sin->sin_addr = in;
                    strncpy(req.arp_dev, iface.c_str(), IFNAMSIZ-1);
                    if (ioctl(fd, SIOCGARP, &req) != -1) {
                        memcpy(gw_info.gw_mac, req.arp_ha.sa_data, 6);
                    }
                    close(fd);
                }
                gateways.push_back(gw_info);
            }
        }
        return gateways;
    }
};


struct Network_event_readable {
    int ifindex;
    unsigned int pkt_len;
    int version;
    int protocol;
    std::string macSrc;
    std::string macDst;
    std::string ipSrc;
    unsigned int portSrc;
    std::string ipDst;
    unsigned int portDst;
    bool is_wan;
    int is_internal_going_to_internet;
};

static Network_event_readable make_readable(const Network_event &ev)
{
    Network_event_readable r{};
    char buf[64];

    r.ifindex = ev.ifindex;
    r.pkt_len = ev.pkt_len;
    r.version = ev.version;
    r.protocol = ev.protocol;

    // MAC 주소: XX:XX:XX:XX:XX:XX 형식 (대문자, 콜론 구분)
    std::snprintf(buf, sizeof(buf),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        ev.macSrc[0], ev.macSrc[1], ev.macSrc[2],
        ev.macSrc[3], ev.macSrc[4], ev.macSrc[5]);
    r.macSrc = buf;

    std::snprintf(buf, sizeof(buf),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        ev.macDst[0], ev.macDst[1], ev.macDst[2],
        ev.macDst[3], ev.macDst[4], ev.macDst[5]);
    r.macDst = buf;

    // IPv4 주소: dotted-decimal notation (제로 패딩 제거)
    // ev.ipSrc는 네트워크 바이트 오더(빅엔디안)로 가정
    struct in_addr addr_src;
    addr_src.s_addr = ev.ipSrc;
    inet_ntop(AF_INET, &addr_src, buf, sizeof(buf));
    r.ipSrc = buf;

    struct in_addr addr_dst;
    addr_dst.s_addr = ev.ipDst;
    inet_ntop(AF_INET, &addr_dst, buf, sizeof(buf));
    r.ipDst = buf;

    r.portSrc = ev.portSrc;
    r.portDst = ev.portDst;
    r.is_wan = ev.is_wan;
    r.is_internal_going_to_internet = ev.is_internal_going_to_internet;

    return r;
}

static bool running = true;
static void sigint(int) { running = false; }
static int handle_event(void *ctx, void *data, size_t len) { 

    Network_event* event = (Network_event*)data;
    if(!event) return 0;

    auto readable_event = make_readable(*event);

    std::cout << readable_event.ipSrc << " -> " << readable_event.ipDst << std::endl;

    return 0;
}

int main()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) { perror("setrlimit failed"); return 1; }

    Forwarder forward;

    struct xdp_prog_bpf *skel = xdp_prog_bpf__open_and_load();
    if (!skel) { std::cerr << "Failed to open/load skeleton\n"; return 1; }

    int map_interface_fd = bpf_map__fd(skel->maps.map_interface_info);
    int map_wan_idx_fd   = bpf_map__fd(skel->maps.map_wan_idx);
    int map_local_ips_fd = bpf_map__fd(skel->maps.map_local_ips); // [NEW]
    int map_ringbuf_fd   = bpf_map__fd(skel->maps.network_ringbuffer);

    forward.SetMapFDs(map_interface_fd, map_wan_idx_fd, map_local_ips_fd);

    if (!forward.PopulateMaps()) {
        std::cerr << "Failed to populate maps\n";
        xdp_prog_bpf__destroy(skel);
        return 1;
    }

    int prog_fd = bpf_program__fd(skel->progs.xdp_packet_handler);
    std::vector<int> attached_ifindices;
    
    struct ifaddrs *ifaddr;
    getifaddrs(&ifaddr);
    std::set<std::string> seen;
    
    for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || strcmp(ifa->ifa_name, "lo") == 0) continue;
        std::string name(ifa->ifa_name);
        if (seen.count(name)) continue;
        seen.insert(name);
        
        int idx = if_nametoindex(ifa->ifa_name);
        if (idx > 0) {
            int err = bpf_xdp_attach(idx, prog_fd, XDP_FLAGS_SKB_MODE, nullptr);
            if (!err) {
                std::cout << "Attached to " << name << " (" << idx << ")\n";
                attached_ifindices.push_back(idx);
            }
        }
    }
    freeifaddrs(ifaddr);

    if (attached_ifindices.empty()) {
        std::cerr << "No interfaces attached.\n";
        xdp_prog_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, sigint);
    struct ring_buffer *rb = ring_buffer__new(map_ringbuf_fd, handle_event, nullptr, nullptr);

    std::cout << "Running...\n";
    while (running) {
        ring_buffer__poll(rb, 5);
    }

    std::cout << "Stopping...\n";
    for (int idx : attached_ifindices) {
        bpf_xdp_detach(idx, XDP_FLAGS_SKB_MODE, nullptr);
    }
    ring_buffer__free(rb);
    xdp_prog_bpf__destroy(skel);
    return 0;
}

