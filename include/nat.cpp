// nat table 만들어서 nat 처리

#include <iostream>
#include <cstdint>
#include <unordered_map>
#include <ctime>
#include <cstring>
#include <netinet/in.h>

#include "./nat.h"
#include "./packets.h"
#include "./common.h"
#include "./router_info.h"

void init_nat_table(){
    auto& info = router_info::instance();

    info.lan_to_wan_table.clear();
    info.wan_to_lan_table.clear();

    info.last_tcp_port_num = 10000;
    info.last_udp_port_num = 10000;
    info.last_icmp_port_num = 10000;

    memset(info.is_tcp_port_allocated, 0, 2501);
    memset(info.is_udp_port_allocated, 0, 2501);
}

bool is_lan_ip( uint32_t ip_address){
    return (ip_address & 0xFF000000) == 0x0A000000; // 10.x.x.x 대역
}

uint64_t make_nat_key(uint32_t ip, uint16_t port, uint8_t protocol) {
    return ((uint64_t)protocol << 56) | ((uint64_t)ip << 16) | port;
}

uint16_t allocate_tcp_port(){
    auto& info = router_info::instance();
    for(int i = 0; i < 20000; ++i){
        int idx = (info.last_tcp_port_num + i) % 20000;
        if((info.is_tcp_port_allocated[idx / 8] & (1 << (idx % 8))) == 0){
            info.is_tcp_port_allocated[idx / 8] |= (1 << (idx % 8));
            info.last_tcp_port_num = idx;
            return idx + 10000;
        }
    }
    return 0; // 포트 부족
}

uint16_t allocate_udp_port(){
    auto& info = router_info::instance();
    for(int i = 0; i < 20000; ++i){
        int idx = (info.last_udp_port_num + i) % 20000;
        if((info.is_udp_port_allocated[idx / 8] & (1 << (idx % 8))) == 0){
            info.is_udp_port_allocated[idx / 8] |= (1 << (idx % 8));
            info.last_udp_port_num = idx;
            return idx + 10000;
        }
    }
    return 0; // 포트 부족
}

uint16_t allocate_icmp_port(){
    auto& info = router_info::instance();
    for(int i = 0; i < 40000; ++i){
        int idx = (info.last_icmp_port_num + i) % 40000;
        if((info.is_icmp_port_allocated[idx / 8] & (1 << (idx % 8))) == 0){
            info.is_icmp_port_allocated[idx / 8] |= (1 << (idx % 8));
            info.last_icmp_port_num = idx;
            return idx + 10000;
        }
    }
    return 0; // 포트 부족
}

void free_tcp_port(uint16_t port){
    uint16_t idx = port - 10000;
    router_info::instance().is_tcp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
}

void free_udp_port(uint16_t port){
    uint16_t idx = port - 10000;
    router_info::instance().is_udp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
}

void update_nat_table(uint64_t key, struct NAT_TABLE_ENTRY& entry){
    entry.last_updated = std::time(nullptr);
    router_info::instance().lan_to_wan_table[key] = entry;
    router_info::instance().wan_to_lan_table[entry.protocol << 16 | entry.external_port] = entry;
}

void update_table_entry_time(struct NAT_TABLE_ENTRY* entry){
    if(entry) entry->last_updated = std::time(nullptr);
}

NAT_TABLE_ENTRY find_nat_entry_by_internal(uint64_t internal_port){
    auto it = router_info::instance().lan_to_wan_table.find(internal_port);
    if(it != router_info::instance().lan_to_wan_table.end()){
        return it->second;
    }
    return NAT_TABLE_ENTRY{0, 0, 0, 0, 0};
}

NAT_TABLE_ENTRY find_nat_entry_by_external(uint8_t protocol, uint16_t external_port){
    auto it = router_info::instance().wan_to_lan_table.find(protocol << 16 | external_port);
    if(it != router_info::instance().wan_to_lan_table.end()){
        return it->second;
    }
    return NAT_TABLE_ENTRY{0, 0, 0, 0, 0};
}

void cleanup_expired_nat_entries() {
    auto& info = router_info::instance();
    time_t current_time = time(NULL);
    
    auto it = info.wan_to_lan_table.begin();
    
    while (it != info.wan_to_lan_table.end()) {
        struct NAT_TABLE_ENTRY entry = it->second;
        double diff = difftime(current_time, entry.last_updated);
        
        int timeout_limit = 1000000;
        switch(entry.protocol){
            case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:
                timeout_limit = info.TCP_TIMEOUT;
                break;
            
            case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:
                timeout_limit = info.UDP_TIMEOUT;
                break;

            case IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL:
                timeout_limit = info.ICMP_TIMEOUT;
                break;
        }
        
        // timeout 적용
        if (diff > timeout_limit) {
            if(info.debug_mode_nat){
                printf("[nat] erasing timeout entry : %d(lan) - %d(wan) \n", entry.internal_port, entry.external_port);
            }

            switch(entry.protocol){
                case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{
                    int idx = entry.external_port - 10000;
                    if(idx >= 0 && idx < 20000) info.is_tcp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
                    uint64_t key_internal = make_nat_key(entry.ip, entry.internal_port, IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL);
                    info.lan_to_wan_table.erase(key_internal);
                    break;
                }
                
                case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{
                    int idx = entry.external_port - 10000;
                    if(idx >= 0 && idx < 20000) info.is_udp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
                    uint64_t key_internal = make_nat_key(entry.ip, entry.internal_port, IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL);
                    info.lan_to_wan_table.erase(key_internal);
                    break;
                }

                case IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL:{
                    int idx = entry.external_port - 10000;
                    if(idx >= 0 && idx < 20000) info.is_icmp_port_allocated[idx / 8] &= ~(1 << (idx % 8));
                    uint64_t key_internal = make_nat_key(entry.ip, entry.internal_port, IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL);
                    info.lan_to_wan_table.erase(key_internal);
                    break;
                }
            }
            
            it = info.wan_to_lan_table.erase(it);
        } else {
            // 만료 안 됐으면 다음으로
            ++it;
        }
    }
}

bool nat_inbound_handler(struct IPV4_HEADER* ipv4_packet){ 
    // wan->lan
    // nat장부에 있으면 true, 아니면 false
    auto& info = router_info::instance();

    uint32_t dst_ip = ipv4_packet->destination_ip;
    uint16_t dst_port;

    switch(ipv4_packet->protocol){
        case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{
            struct TCP_HEADER* tcp_packet = reinterpret_cast<struct TCP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            uint16_t key_internal = ntohs(tcp_packet->destination_port);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_external(IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL, key_internal);

            if(memcmp(&nat_entry, &info.void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 드롭
                return false;
            }

            tcp_packet->destination_port = htons(nat_entry.internal_port);
            ipv4_packet->destination_ip = nat_entry.ip;
            update_table_entry_time(&nat_entry);

            tcp_calculate_checksum(tcp_packet, ipv4_packet);
            return true;
            // break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{
            struct UDP_HEADER* udp_packet = reinterpret_cast<struct UDP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            uint16_t key_internal = ntohs(udp_packet->destination_port);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_external(IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL, key_internal);

            if(memcmp(&nat_entry, &info.void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 드롭
                return false;
            }

            udp_packet->destination_port = htons(nat_entry.internal_port);
            ipv4_packet->destination_ip = nat_entry.ip;
            update_table_entry_time(&nat_entry);

            udp_calculate_checksum(udp_packet, ipv4_packet);
            return true;
            // break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL:{
            struct ICMP_HEADER* icmp_packet = reinterpret_cast<struct ICMP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            uint16_t key_internal = ntohs(icmp_packet->identifier);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_external(IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL, key_internal);

            if(memcmp(&nat_entry, &info.void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 드롭
                return false;
            }

            icmp_packet->identifier = htons(nat_entry.internal_port);
            ipv4_packet->destination_ip = nat_entry.ip;
            update_table_entry_time(&nat_entry);

            icmp_calculate_checksum(icmp_packet, ipv4_packet); // 여기 확인
            return true;
        }

        default:{
            return false;
            // break;
        }
    }
}

void nat_outbound_handler(struct IPV4_HEADER* ipv4_packet){
    auto& info  = router_info::instance();

     // lan -> wan
    uint32_t src_ip = ipv4_packet->source_ip;
    uint16_t src_port;

    switch(ipv4_packet->protocol){
        case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{
            struct TCP_HEADER* tcp_packet = reinterpret_cast<struct TCP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            src_port = ntohs(tcp_packet->source_port);

            uint64_t key_internal = make_nat_key(src_ip, src_port, IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_internal(key_internal);

            if(memcmp(&nat_entry, &info.void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 새로 할당 (allocate_tcp_port)
                nat_entry.ip = src_ip;
                nat_entry.internal_port = ntohs(tcp_packet->source_port);
                nat_entry.protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL; // TCP

                // 외부 포트 할당
                uint16_t external_port = allocate_tcp_port();
                if(external_port == 0){
                    if(info.debug_mode_nat){
                        printf("[nat] can't allocate new outbound port\n");
                    }
                    return; // 포트 부족
                }
                nat_entry.external_port = external_port;
                update_nat_table(key_internal, nat_entry);

                if(info.debug_mode_nat){
                    printf("[nat] adding new outbound session  %d(lan) - %d(wan) \n", nat_entry.internal_port, nat_entry.external_port);
                }
            }else{
            // 포트 할당 되어있으면 그대로 사용
            // 이미 할당된 포트 있음 -> 시간 갱신
                update_table_entry_time(&nat_entry);
            }

            // 할당된 포트로 tcp 패킷 변조
            tcp_packet->source_port = htons(nat_entry.external_port);
            ipv4_packet->source_ip = info.my_ipv4_wan_ip;

            // checksum 재계산
            tcp_calculate_checksum(tcp_packet, ipv4_packet);
            break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{
            struct UDP_HEADER* udp_packet = reinterpret_cast<struct UDP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            src_port = ntohs(udp_packet->source_port);

            uint64_t key_internal = make_nat_key(src_ip, src_port, IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_internal(key_internal);

            if(memcmp(&nat_entry, &info.void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 새로 할당 (allocate_tcp_port)
                nat_entry.ip = ipv4_packet->source_ip;
                nat_entry.internal_port = ntohs(udp_packet->source_port);
                nat_entry.protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL; // UDP

                // 외부 포트 할당
                uint16_t external_port = allocate_udp_port();
                if(external_port == 0){
                    return; // 포트 부족
                }

                nat_entry.external_port = external_port;
            }else{
            // 포트 할당 되어있으면 그대로 사용
            // 이미 할당된 포트 있음 -> 시간 갱신
                update_table_entry_time(&nat_entry);
            }

            // 할당된 포트로 udp 패킷 변조
            udp_packet->source_port = htons(nat_entry.external_port);
            ipv4_packet->source_ip = info.my_ipv4_wan_ip;
            
            update_nat_table(key_internal, nat_entry);

            // checksum 재계산
            udp_calculate_checksum(udp_packet, ipv4_packet);
            break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL:{
            struct ICMP_HEADER* icmp_packet = reinterpret_cast<struct ICMP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            src_port = ntohs(icmp_packet->identifier);

            uint64_t key_internal = make_nat_key(src_ip, src_port, IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_internal(key_internal);

            if(memcmp(&nat_entry, &info.void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 새로 할당 (allocate_tcp_port)
                nat_entry.ip = ipv4_packet->source_ip;
                nat_entry.internal_port = ntohs(icmp_packet->identifier);
                nat_entry.protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL; // ICMP

                // 외부 포트 할당
                uint16_t external_port = allocate_icmp_port();
                if(external_port == 0){
                    return; // 포트 부족
                }

                nat_entry.external_port = external_port;
            }else{
            // 포트 할당 되어있으면 그대로 사용
            // 이미 할당된 포트 있음 -> 시간 갱신
                update_table_entry_time(&nat_entry);
            }

            // 할당된 포트로 udp 패킷 변조
            icmp_packet->identifier = htons(nat_entry.external_port);
            ipv4_packet->source_ip = info.my_ipv4_wan_ip;
            
            update_nat_table(key_internal, nat_entry);

            // checksum 재계산
            icmp_calculate_checksum(icmp_packet, ipv4_packet);
            break;
        }

        default:{
            break;
        }
    }
}