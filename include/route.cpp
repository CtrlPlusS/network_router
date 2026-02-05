#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>

#include "./route.h"
#include "./router_info.h"

void init_routing_table() {
    auto& info = router_info::instance();
    info.routing_table.clear();

    struct ROUTE_ENTRY default_gateway;
    default_gateway.gateway = info.my_ipv4_wan_gateway;
    default_gateway.destination = inet_addr("0.0.0.0");
    default_gateway.netmask = inet_addr("0.0.0.0");
    default_gateway.metric = 99;
    strncpy(default_gateway.interface, info.my_interface_wan.c_str(), 15);
    info.routing_table.push_back(default_gateway); // 기본 게이트웨이
    
    struct ROUTE_ENTRY loopback;
    loopback.destination = inet_addr("127.0.0.0");
    loopback.netmask = inet_addr("255.0.0.0");
    loopback.gateway = inet_addr("0.0.0.0");
    strncpy(loopback.interface, "lo", 15);
    loopback.metric = 1;
    info.routing_table.push_back(loopback); // 루프백

    struct ROUTE_ENTRY lan_route;
    lan_route.netmask = inet_addr("255.255.255.0");
    lan_route.destination = info.my_ipv4_lan_ip & lan_route.netmask;
    lan_route.gateway = inet_addr("0.0.0.0");
    strncpy(lan_route.interface, info.my_interface_lan.c_str(), 15);
    lan_route.metric = 1;
    info.routing_table.push_back(lan_route); // 내부망

    struct ROUTE_ENTRY wan_route;
    wan_route.netmask = inet_addr("255.255.255.0");
    wan_route.destination = info.my_ipv4_wan_ip & wan_route.netmask;
    wan_route.gateway = inet_addr("0.0.0.0");
    strncpy(wan_route.interface, info.my_interface_wan.c_str(), 15);
    wan_route.metric = 10;
    info.routing_table.push_back(wan_route); // 외부망

    std::sort(info.routing_table.begin(), info.routing_table.end(), [](const ROUTE_ENTRY& a, const ROUTE_ENTRY& b) {
        if (a.netmask != b.netmask) 
            return a.netmask > b.netmask;
        return a.metric < b.metric;
    });
}

/**
* @brief Find the routing table entry for the given source IP
* @param src Source IP address
* @return Corresponding ROUTE_ENTRY structure
 */
struct ROUTE_ENTRY routing_table_find(uint32_t src) {
    // 각 테이블마다 튜플로 입력
    // destination(uint32_t), netmask(uint32_t), gateway(uint32_t), interface(char[16]), metric(int)
    for (const auto& entry : router_info::instance().routing_table) {
        if ((src & entry.netmask) == (entry.destination & entry.netmask)) {
            return entry;
        }
    }

    // 못찾음
    return router_info::instance().routing_table.back();
}