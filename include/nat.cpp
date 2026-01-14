// nat table 만들어서 nat 처리

#include <iostream>
#include <cstdint>
#include <unordered_map>
#include <ctime>
#include <cstring>
#include <netinet/in.h>

#include "./nat.h"

extern bool debug_mode_nat;

std::unordered_map<uint64_t, NAT_TABLE_ENTRY> lan_to_wan_table; // 키: 내부 IP(32비트) + 내부 포트(16비트))
std::unordered_map<uint16_t, NAT_TABLE_ENTRY> wan_to_lan_table; // 키: 외부 포트(16비트)

uint16_t tcp_port_num; // 내부 포트 할당 시작점
uint16_t udp_port_num; // 외부 포트 할당 시작점

uint16_t last_tcp_port_num;
uint16_t last_udp_port_num;

uint8_t is_tcp_port_allocated[4096];
uint8_t is_udp_port_allocated[4096];

void init_nat_table(){
    lan_to_wan_table.clear();
    wan_to_lan_table.clear();

    last_tcp_port_num = 10000;
    last_udp_port_num = 10000;

    memset(is_tcp_port_allocated, 0, 4096);
    memset(is_udp_port_allocated, 0, 4096);
}

bool is_lan_ip( uint32_t ip_address){
    return (ip_address & 0xFF000000) == 0x0A000000; // 10.x.x.x 대역
}

uint16_t allocate_tcp_port(){
    for(int i = 0; i < 32768; ++i){
        int idx = (last_tcp_port_num + i) % 32768;
        if((is_tcp_port_allocated[idx / 8] & (1 << (idx % 8))) == 0){
            is_tcp_port_allocated[idx / 8] |= (1 << (idx % 8));
            last_tcp_port_num = idx;
            if(debug_mode_nat){
                printf("[nat] allocated tcp port : %d\n", idx + 10000);
            }
            return idx + 10000;
        }
    }
    return 0; // 포트 부족
}

uint16_t allocate_udp_port(){
    for(int i = 0; i < 32768; ++i){
        int idx = (last_udp_port_num + i) % 32768;
        if((is_udp_port_allocated[idx / 8] & (1 << (idx % 8))) == 0){
            is_udp_port_allocated[idx / 8] |= (1 << (idx % 8));
            last_udp_port_num = idx;
            if(debug_mode_nat){
                printf("[nat] allocated udp port : %d\n", idx + 10000);
            }
            return idx + 10000;
        }
    }
    return 0; // 포트 부족
}

void free_tcp_port(uint16_t port){
    uint16_t idx = port - 10000;
    is_tcp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
}

void free_udp_port(uint16_t port){
    uint16_t idx = port - 10000;
    is_udp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
}

void update_nat_table(uint64_t key, struct NAT_TABLE_ENTRY& entry){
    entry.last_updated = std::time(nullptr);
    lan_to_wan_table[key] = entry;
    wan_to_lan_table[entry.external_port] = entry;

    if(debug_mode_nat){
        printf("[nat] nat table updated : %d.%d.%d.%d (%d) -> (%d) (raw value)\n",
            (entry.ip >> 24) & 0xFF,
            (entry.ip >> 16) & 0xFF,
            (entry.ip >>  8) & 0xFF,
            (entry.ip      ) & 0xFF,
            entry.internal_port,
            entry.external_port);
    }
}

void update_table_entry_time(struct NAT_TABLE_ENTRY* entry){
    if(entry) entry->last_updated = std::time(nullptr);
}

NAT_TABLE_ENTRY find_nat_entry_by_internal(uint64_t internal_port){
    auto it = lan_to_wan_table.find(internal_port);
    if(it != lan_to_wan_table.end()){
        return it->second;
    }
    return NAT_TABLE_ENTRY{0, 0, 0, 0, 0};
}

NAT_TABLE_ENTRY find_nat_entry_by_external(uint16_t external_port){
    auto it = wan_to_lan_table.find(external_port);
    if(it != wan_to_lan_table.end()){
        return it->second;
    }
    return NAT_TABLE_ENTRY{0, 0, 0, 0, 0};
}

void cleanup_expired_nat_entries(){
    const int timeout_seconds = 60; // 60초 동안 사용되지 않은 엔트리 삭제
    time_t current_time = std::time(nullptr);

    for(auto it = lan_to_wan_table.begin(); it != lan_to_wan_table.end(); ){
        if(current_time - it->second.last_updated > timeout_seconds){
            // 외부 포트도 해제
            free_tcp_port(it->second.external_port); // TCP 포트 해제
            free_udp_port(it->second.external_port); // UDP 포트 해제
            wan_to_lan_table.erase(it->second.external_port);
            it = lan_to_wan_table.erase(it);
        } else {
            ++it;
        }
    }
}

