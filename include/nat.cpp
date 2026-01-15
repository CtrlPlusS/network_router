// nat table 만들어서 nat 처리

#include <iostream>
#include <cstdint>
#include <unordered_map>
#include <ctime>
#include <cstring>
#include <netinet/in.h>

#include "./nat.h"
#include "./packets.h"

extern bool debug_mode_nat;

std::unordered_map<uint64_t, NAT_TABLE_ENTRY> lan_to_wan_table; // 키: 내부 IP(32비트) + 내부 포트(16비트))
std::unordered_map<uint16_t, NAT_TABLE_ENTRY> wan_to_lan_table; // 키: 외부 포트(16비트)

uint16_t tcp_port_num; // 내부 포트 할당 시작점
uint16_t udp_port_num; // 외부 포트 할당 시작점

uint16_t last_tcp_port_num;
uint16_t last_udp_port_num;

uint8_t is_tcp_port_allocated[2501];
uint8_t is_udp_port_allocated[2501];

void init_nat_table(){
    lan_to_wan_table.clear();
    wan_to_lan_table.clear();

    last_tcp_port_num = 10000;
    last_udp_port_num = 30000;

    memset(is_tcp_port_allocated, 0, 2501);
    memset(is_udp_port_allocated, 0, 2501);
}

bool is_lan_ip( uint32_t ip_address){
    return (ip_address & 0xFF000000) == 0x0A000000; // 10.x.x.x 대역
}

uint16_t allocate_tcp_port(){
    for(int i = 0; i < 20000; ++i){
        int idx = (last_tcp_port_num + i) % 20000;
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
    for(int i = 0; i < 20000; ++i){
        int idx = (last_udp_port_num + i) % 20000;
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

const int TCP_TIMEOUT = 60;
const int UDP_TIMEOUT = 30;

void cleanup_expired_nat_entries() {
    time_t current_time = time(NULL);
    
    // wan_to_lan_table을 순회하며 검사 (외부 포트가 Key이므로 관리가 쉬움)
    auto it = wan_to_lan_table.begin();
    
    while (it != wan_to_lan_table.end()) {
        struct NAT_TABLE_ENTRY entry = it->second;
        double diff = difftime(current_time, entry.last_updated);
        
        int timeout_limit = (entry.protocol == IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL) 
                            ? TCP_TIMEOUT : UDP_TIMEOUT;

        if (diff > timeout_limit) {
            // [만료됨!] 삭제 진행
            
            // 1. 포트 반납 (사용 가능 상태로 변경)
            if (entry.protocol == IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL) {
                // 포트 번호 - 시작 번호(10000) = 인덱스
                int idx = entry.external_port - 10000;
                if(idx >= 0 && idx < 4096) is_tcp_port_allocated[idx] = false;
            } else {
                // 포트 번호 - 시작 번호(30000) = 인덱스
                int idx = entry.external_port - 30000;
                if(idx >= 0 && idx < 4096) is_udp_port_allocated[idx] = false;
            }

            // 2. lan_to_wan_table(내부용 장부)에서도 삭제
            // 키를 다시 만들어야 함 (Internal IP + Port)
            uint64_t key_internal = (0x8000000000000000ULL) | 
                                    ((uint64_t)entry.ip << 16) | 
                                    entry.internal_port;
            
            lan_to_wan_table.erase(key_internal);

            // 3. wan_to_lan_table(외부용 장부)에서 삭제하고 반복자 갱신
            // erase는 삭제 후 다음 요소의 반복자를 반환함
            it = wan_to_lan_table.erase(it);

            // printf("[NAT] Expired entry removed. Port: %d\n", entry.external_port);
        } else {
            // 만료 안 됐으면 다음으로
            ++it;
        }
    }
}

