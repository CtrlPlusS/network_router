#include <iostream>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>

#include "./route.h"

bool debug_mode_route = false;

std::vector<ROUTE_ENTRY> routing_table;
struct ROUTE_ENTRY default_gateway = {
    .destination = inet_addr("0.0.0.0"),
    .netmask = inet_addr("0.0.0.0"),
    .gateway = inet_addr("10.0.0.1"),
    .interface = "enxb0386cf1284b",
    .metric = 99
};

void routing_table_init() {
    routing_table.clear();

    routing_table.push_back(default_gateway); // 기본 게이트웨이
    routing_table.push_back({
        .destination = inet_addr("127.0.0.0"),
        .netmask = inet_addr("255.0.0.0"),
        .gateway = inet_addr("0.0.0.0"),
        .interface = "lo",
        .metric = 1
    }); // 루프백
    routing_table.push_back({
        .destination = inet_addr("10.0.0.0"),
        .netmask = inet_addr("255.255.255.0"),
        .gateway = inet_addr("0.0.0.0"),
        .interface = "enxb0386cf1284b",
        .metric = 1
    }); // 10.0.0.0/24
    routing_table.push_back({
        .destination = inet_addr("8.8.8.0"),
        .netmask = inet_addr("255.255.255.0"),
        .gateway = inet_addr("192.168.0.1"),
        .interface = "wlan0",
        .metric = 10
    }); // 8.8.8.0/24 (외부망 테스트)

    std::sort(routing_table.begin(), routing_table.end(), [](const ROUTE_ENTRY& a, const ROUTE_ENTRY& b) {
        if (a.netmask != b.netmask) 
            return a.netmask > b.netmask;
        return a.metric < b.metric;
    });

    if(debug_mode_route){
        printf("=== Routing Table ===\n");
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