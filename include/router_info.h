#ifndef ROUTER_INFO_H
#define ROUTER_INFO_H

#include <cstdint>
#include <arpa/inet.h>
#include <string>
#include <queue>
#include <vector>
#include <map>
#include <unordered_map>

#include "./json.hpp"
#include "./packets.h"

using json = nlohmann::json;

enum FIREWALL_ACTION_CONSTANTS : uint8_t {
    ACCEPT = 0,
    DROP = 1,
    REJECT = 2, // 차단 메시지 전송
};

struct FIREWALL_TABLE_ENTRY {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t protocol;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t action;
};

struct NAT_TABLE_ENTRY {
    uint32_t ip;
    uint16_t internal_port;
    uint16_t external_port;
    uint8_t protocol; // 1: ICMP, 6: TCP, 17: UDP
    time_t last_updated;
};

struct ROUTE_ENTRY {
    uint32_t destination; // 목적지 네트워크 주소
    uint32_t netmask;     // 서브넷 마스크
    uint32_t gateway;    // 게이트웨이 주소
    char interface[16];  // 출구 인터페이스 이름
    int metric;        // 메트릭 값
};

class router_info {
public:
    static router_info& instance(){
        static router_info info;
        return info;
    }

    std::string config_file_pwd = "/home/konan0207/router_project/src/config.json"; // = "/home/konan0207/router_project/src/config.json";

    // firewall
    std::vector<FIREWALL_TABLE_ENTRY> firewall_table;

    // nat
    std::unordered_map<uint64_t, NAT_TABLE_ENTRY> lan_to_wan_table;
    std::unordered_map<uint32_t, NAT_TABLE_ENTRY> wan_to_lan_table;
    struct NAT_TABLE_ENTRY void_entry = {0,0,0,0,0};

    uint16_t tcp_port_num = 10000; // 내부 포트 할당 시작점
    uint16_t udp_port_num = 10000; // 외부 포트 할당 시작점

    uint16_t last_tcp_port_num = 0;
    uint16_t last_udp_port_num = 0;
    uint16_t last_icmp_port_num = 0;

    uint8_t is_tcp_port_allocated[2501] = {0};
    uint8_t is_udp_port_allocated[2501] = {0};
    uint8_t is_icmp_port_allocated[2501] = {0};

    int TCP_TIMEOUT = 300;
    int UDP_TIMEOUT = 120;
    int ICMP_TIMEOUT = 60;

    // arp
    std::unordered_map<uint32_t, struct MAC_ADDRESS> arp_table;
    std::unordered_map<uint32_t, std::queue<std::vector<char>>> pending_packets;

    // route
    std::vector<ROUTE_ENTRY> routing_table;

    // dhcp
    std::pair<bool, time_t> allocated_dhcp_ip_table[253];
    
    uint8_t dhcp_ip_start_num = 2;
    uint8_t dhcp_ip_end_num = 254;
    uint16_t dhcp_offering_time = 3600;
    uint32_t dhcp_dns_server = inet_addr("8.8.8.8");

    // router info
    struct MAC_ADDRESS my_mac_lan = {0};
    struct MAC_ADDRESS my_mac_wan = {0};

    uint32_t my_ipv4_lan_ip = 0;
    uint32_t my_ipv4_wan_ip = 0;

    uint32_t my_ipv4_lan_gateway = 0;
    uint32_t my_ipv4_wan_gateway = 0;

    std::string my_interface_lan;
    std::string my_interface_wan;

    // debug
    bool debug_mode_core = true;
    bool debug_mode_traffic = false;
    bool debug_mode_nat = false;
    bool debug_mode_dhcp = false;
    bool debug_mode_security = false;

    void init_router_info();
    void load_config();

private:
    std::string exec_command(const char* command);
    void get_lan_info(int sock);
    void get_wan_info(int sock);

    router_info() = default;
    ~router_info() = default;

    // 복사 방지
    router_info(const router_info&) = delete;
    router_info& operator=(const router_info&) = delete;
};

#endif