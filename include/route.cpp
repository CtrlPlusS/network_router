#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>

#include "./route.h"
#include "./router_info.h"

extern bool debug_mode_route;

extern struct MAC_ADDRESS my_mac_lan; // = {0x2c, 0xcf, 0x67, 0x2e, 0x1f, 0x85};
extern struct MAC_ADDRESS my_mac_wan; // = {0xb0, 0x38, 0x6c, 0xf1, 0x28, 0x4b};

extern uint32_t my_ipv4_lan_ip; // 내부망 ip
extern uint32_t my_ipv4_lan_gateway;
extern uint32_t my_ipv4_wan_ip; // 외부망 ip
extern uint32_t my_ipv4_wan_gateway;

extern std::string my_interface_lan;
extern std::string my_interface_wan;

std::vector<ROUTE_ENTRY> routing_table;
struct ROUTE_ENTRY default_gateway;

void init_routing_table() {
    routing_table.clear();

    default_gateway.gateway = my_ipv4_wan_gateway;
    default_gateway.destination = inet_addr("0.0.0.0");
    default_gateway.netmask = inet_addr("0.0.0.0");
    default_gateway.metric = 99;
    strncpy(default_gateway.interface, my_interface_wan.c_str(), 15);
    routing_table.push_back(default_gateway); // 기본 게이트웨이
    
    struct ROUTE_ENTRY loopback;
    loopback.destination = inet_addr("127.0.0.0");
    loopback.netmask = inet_addr("255.0.0.0");
    loopback.gateway = inet_addr("0.0.0.0");
    strncpy(loopback.interface, "lo", 15);
    loopback.metric = 1;
    routing_table.push_back(loopback); // 루프백

    struct ROUTE_ENTRY lan_route;
    lan_route.netmask = inet_addr("255.255.255.0");
    lan_route.destination = my_ipv4_lan_ip & lan_route.netmask;
    lan_route.gateway = inet_addr("0.0.0.0");
    strncpy(lan_route.interface, my_interface_lan.c_str(), 15);
    lan_route.metric = 1;
    routing_table.push_back(lan_route); // 내부망

    struct ROUTE_ENTRY wan_route;
    wan_route.netmask = inet_addr("255.255.255.0");
    wan_route.destination = my_ipv4_wan_ip & wan_route.netmask;
    wan_route.gateway = inet_addr("0.0.0.0");
    strncpy(wan_route.interface, my_interface_wan.c_str(), 15);
    wan_route.metric = 10;
    routing_table.push_back(wan_route); // 외부망

    std::sort(routing_table.begin(), routing_table.end(), [](const ROUTE_ENTRY& a, const ROUTE_ENTRY& b) {
        if (a.netmask != b.netmask) 
            return a.netmask > b.netmask;
        return a.metric < b.metric;
    });

    if(debug_mode_route){
        printf("[route] === Routing Table(dest, mask, gate htonl 적용됨) ===\n");
        for(const auto& entry : routing_table){
            uint32_t dest = htonl(entry.destination);
            uint32_t mask = htonl(entry.netmask);
            uint32_t gate = htonl(entry.gateway);

            printf("%d.%d.%d.%d\t%d.%d.%d.%d\t%d.%d.%d.%d\t%s\t%d\n",
                dest >> 24 & 0xFF,
                dest >> 16 & 0xFF,
                dest >> 8 & 0xFF,
                dest & 0xFF,
                mask >> 24 & 0xFF,
                mask >> 16 & 0xFF,
                mask >> 8 & 0xFF,
                mask & 0xFF,
                gate >> 24 & 0xFF,
                gate >> 16 & 0xFF,
                gate >> 8 & 0xFF,
                gate & 0xFF,
                entry.interface,
                entry.metric);
        }
        printf("=====================\n");
    }
}

/**
* @brief Find the routing table entry for the given source IP
* @param src Source IP address
* @return Corresponding ROUTE_ENTRY structure
 */
struct ROUTE_ENTRY routing_table_find(uint32_t src) {
    // 각 테이블마다 튜플로 입력
    // destination(uint32_t), netmask(uint32_t), gateway(uint32_t), interface(char[16]), metric(int)
    for (const auto& entry : routing_table) {
        if ((src & entry.netmask) == (entry.destination & entry.netmask)) {
            return entry;
        }
    }

    return default_gateway;
}