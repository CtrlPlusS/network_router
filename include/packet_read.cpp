// 패킷 읽고 처리까지. 
// 전송은 packet_send.cpp에서 처리

#include <cstdint>
#include <iostream>

#include <cstring>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "./nat.h"
#include "./common.h"
#include "./packets.h"
#include "./router_info.h"
#include "./packet_read.h"
#include "./route.h"

extern bool debug_mode_packet_read;

extern MAC_ADDRESS mac_lan;
extern MAC_ADDRESS mac_wan;

extern uint32_t my_ipv4_lan_ip;
extern uint32_t my_ipv4_wan_ip;

struct NAT_TABLE_ENTRY void_entry = {0,0,0,0,0}; 

bool nat_inbound_handler(struct IPV4_HEADER* ipv4_packet){ 
    // wan->lan
    // nat장부에 있으면 true, 아니면 false

    if(debug_mode_packet_read){
        printf("[packet_read] nat_inbound_handler activated\n");
    }

    uint32_t dst_ip = ipv4_packet->destination_ip;
    uint16_t dst_port;

    switch(ipv4_packet->protocol){
        case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{
            struct TCP_HEADER* tcp_packet = reinterpret_cast<struct TCP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            uint16_t key_internal = ntohs(tcp_packet->destination_port);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_external(key_internal);

            if(memcmp(&nat_entry, &void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 드롭
                if(debug_mode_packet_read){
                    printf("[packet_read] can't find %d in TCP NAT. Dropping packet.\n", key_internal);
                }
                return false;
            }

            tcp_packet->destination_port = htons(nat_entry.internal_port);
            ipv4_packet->destination_ip = nat_entry.ip;
            update_table_entry_time(&nat_entry);

            if(debug_mode_packet_read){
                printf("[packet_read] tcp nat_inbound activated. %d.%d.%d.%d(%d) -> %d.%d.%d.%d(%d)\n",
                        (ntohl(ipv4_packet->source_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->source_ip)         ) & 0xFF,
                        ntohs(tcp_packet->source_port),
                        (ntohl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip)      ) & 0xFF,
                        ntohs(tcp_packet->destination_port));
            }

            tcp_calculate_checksum(tcp_packet, ipv4_packet);
            return true;
            // break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{
            struct UDP_HEADER* udp_packet = reinterpret_cast<struct UDP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            uint16_t key_internal = ntohs(udp_packet->destination_port);
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_external(key_internal);

            if(memcmp(&nat_entry, &void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 드롭
                if(debug_mode_packet_read){
                    printf("[packet_read] can't find %d in UDP NAT. Dropping packet.\n", key_internal);
                }
                return false;
            }

            udp_packet->destination_port = htons(nat_entry.internal_port);
            ipv4_packet->destination_ip = nat_entry.ip;
            update_table_entry_time(&nat_entry);

            if(debug_mode_packet_read){
                printf("[packet_read] udp nat_inbound activated. %d.%d.%d.%d(%d) -> %d.%d.%d.%d(%d)\n",
                        (ntohl(ipv4_packet->source_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->source_ip)         ) & 0xFF,
                        ntohs(udp_packet->source_port),
                        (ntohl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip)      ) & 0xFF,
                        ntohs(udp_packet->destination_port));
            }

            udp_calculate_checksum(udp_packet, ipv4_packet);
            return true;
            // break;
        }

        default:{ // icmp?
            return false;
            // break;
        }
    }
}

void nat_outbound_handler(struct IPV4_HEADER* ipv4_packet){
     // lan -> wan
    uint32_t src_ip = ipv4_packet->source_ip;
    uint16_t src_port;

    switch(ipv4_packet->protocol){
        case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{
            struct TCP_HEADER* tcp_packet = reinterpret_cast<struct TCP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            src_port = ntohs(tcp_packet->source_port);

            uint64_t key_internal = (0x8000000000000000ULL) | (uint64_t)src_ip << 16 | src_port;
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_internal(key_internal);

            if(memcmp(&nat_entry, &void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 새로 할당 (allocate_tcp_port)
                nat_entry.ip = src_ip;
                nat_entry.internal_port = ntohs(tcp_packet->source_port);
                nat_entry.protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL; // TCP

                // 외부 포트 할당
                uint16_t external_port = allocate_tcp_port();
                if(external_port == 0){
                    if(debug_mode_packet_read){
                        printf("[packet_read] No available TCP ports for NAT.\n");
                    }
                    return; // 포트 부족
                }
                nat_entry.external_port = external_port;

                update_nat_table(key_internal, nat_entry);
            }else{
            // 포트 할당 되어있으면 그대로 사용
            // 이미 할당된 포트 있음 -> 시간 갱신
                update_table_entry_time(&nat_entry);
            }

            // 할당된 포트로 tcp 패킷 변조
            tcp_packet->source_port = htons(nat_entry.external_port);
            ipv4_packet->source_ip = my_ipv4_wan_ip;

            if(debug_mode_packet_read){
                printf("[packet_read] tcp nat_outbound activated. %d.%d.%d.%d(%d) -> %d.%d.%d.%d(%d)\n",
                        (ntohl(ipv4_packet->source_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->source_ip)      ) & 0xFF,
                        ntohs(tcp_packet->source_port),
                        (ntohl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip)      ) & 0xFF,
                        ntohs(tcp_packet->destination_port));
            }

            // checksum 재계산
            tcp_calculate_checksum(tcp_packet, ipv4_packet);
            break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{
            struct UDP_HEADER* udp_packet = reinterpret_cast<struct UDP_HEADER*>(
                (uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
            );

            src_port = ntohs(udp_packet->source_port);

            uint64_t key_internal = (0x8000000000000000ULL) | (uint64_t)src_ip << 16 | src_port;
            struct NAT_TABLE_ENTRY nat_entry = find_nat_entry_by_internal(key_internal);

            if(memcmp(&nat_entry, &void_entry, sizeof(NAT_TABLE_ENTRY)) == 0){
                // 포트 할당 안되어있으면 새로 할당 (allocate_tcp_port)
                nat_entry.ip = ipv4_packet->source_ip;
                nat_entry.internal_port = ntohs(udp_packet->source_port);
                nat_entry.protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL; // UDP

                // 외부 포트 할당
                uint16_t external_port = allocate_udp_port();
                if(external_port == 0){
                    if(debug_mode_packet_read){
                        printf("[packet_read] No available UDP ports for NAT.\n");
                    }
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
            ipv4_packet->source_ip = my_ipv4_wan_ip;
            
            update_nat_table(key_internal, nat_entry);

            if(debug_mode_packet_read){
                printf("[packet_read] udp nat_outbound activated. %d.%d.%d.%d(%d) -> %d.%d.%d.%d(%d)\n",
                        (ntohl(ipv4_packet->source_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->source_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->source_ip)      ) & 0xFF,
                        ntohs(udp_packet->source_port),
                        (ntohl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip) >>  8) & 0xFF,
                        (ntohl(ipv4_packet->destination_ip)      ) & 0xFF,
                        ntohs(udp_packet->destination_port));
            }

            // checksum 재계산
            udp_calculate_checksum(udp_packet, ipv4_packet);
            break;
        }

        default:{// icmp?
            break;
        }
    }
}


void my_packet_icmp_handler(struct IPV4_HEADER* ipv4_packet){
    struct ICMP_HEADER* icmp_packet = reinterpret_cast<struct ICMP_HEADER*>(
            (char*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
        );

    if(icmp_packet->type == 8){ // 응답 요청
        icmp_packet->type = 0; // 응답으로 변경

        // checksum 재계산
        icmp_packet->checksum = 0;
        icmp_packet->checksum = calculate_checksum(
            (uint16_t*)icmp_packet, ntohs(ipv4_packet->total_length) - (ipv4_packet->version_ihl & 0x0F) * 4);

        if(debug_mode_packet_read){
            printf("[packet_read] ICMP packet received and Echo Request processed.\n");
        }
    }
}

void my_packet_handler(struct IPV4_HEADER* ipv4_packet){

    switch(ipv4_packet->protocol) {
        case IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL:{ // ICMP
            // ICMP 패킷 처리
            // if(debug_mode_packet_read){
            //     printf("[packet_read] ICMP packet received.\n");
            // }
            my_packet_icmp_handler(ipv4_packet);
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{ // TCP
            // TCP 패킷 처리 (생략)
            // if(debug_mode_packet_read){
            //     printf("[packet_read] TCP packet received.\n");
            // }
            // my_packet_tcp_handler(ipv4_packet);
            break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{ // UDP
            // UDP 패킷 처리

            // if(debug_mode_packet_read){
            //     printf("[packet_read] UDP packet received.\n");
            // }

            // my_packet_udp_handler(ipv4_packet);
            break;
        }

        default:{
            // if(debug_mode_packet_read){
            //     printf("[packet_read] Unknown protocol packet received. No action taken.\n");
            // }
            break;
        }
    }
}

uint32_t ipv4_read_handler(char* buffer){
    struct IPV4_HEADER *ipv4_packet = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    // 루프백 패킷 드롭
    if((ntohl(ipv4_packet->destination_ip) >> 24) == 127)
        return 0;

    // 멀티캐스트 패킷 드롭
    if((ntohl(ipv4_packet->destination_ip) & 0xF0000000) == 0xE0000000)
        return 0;

    if(ipv4_packet->source_ip == my_ipv4_wan_ip)
        return 0;

    if(ipv4_packet->source_ip == ipv4_packet->destination_ip)
        return 0;

    if(ipv4_packet->time_to_live <= 1){ // TTL 만료 시 패킷 드롭
        struct ETH_HEADER *eth = reinterpret_cast<struct ETH_HEADER*>(buffer);
        if(debug_mode_packet_read){
            printf("[packet_read] %x:%x:%x:%x:%x:%x(%d.%d.%d.%d)-> %x:%x:%x:%x:%x:%x(%d.%d.%d.%d) TTL expired, dropping packet\n",
                eth->source_mac[0], eth->source_mac[1], eth->source_mac[2],
                eth->source_mac[3], eth->source_mac[4], eth->source_mac[5],
                (htonl(ipv4_packet->source_ip) >> 24) & 0xFF,
                (htonl(ipv4_packet->source_ip) >> 16) & 0xFF,
                (htonl(ipv4_packet->source_ip) >> 8) & 0xFF,
                (htonl(ipv4_packet->source_ip)) & 0xFF,
                eth->destination_mac[0], eth->destination_mac[1], eth->destination_mac[2],
                eth->destination_mac[3], eth->destination_mac[4], eth->destination_mac[5],
                (htonl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                (htonl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                (htonl(ipv4_packet->destination_ip) >> 8) & 0xFF,
                (htonl(ipv4_packet->destination_ip)) & 0xFF);
        }
        return 0;
    }

    if(debug_mode_packet_read){
        printf("[packet_read] packet read! %d.%d.%d.%d(%s) -> %d.%d.%d.%d(%s) (Len: %d, protocol: %d)\n", 
            (htonl(ipv4_packet->source_ip) >> 24) & 0xFF,
            (htonl(ipv4_packet->source_ip) >> 16) & 0xFF,
            (htonl(ipv4_packet->source_ip) >> 8) & 0xFF,
            (htonl(ipv4_packet->source_ip)) & 0xFF,
            is_lan_ip(ntohl(ipv4_packet->source_ip)) ? "lan" : "wan",
            (htonl(ipv4_packet->destination_ip) >> 24) & 0xFF,
            (htonl(ipv4_packet->destination_ip) >> 16) & 0xFF,
            (htonl(ipv4_packet->destination_ip) >> 8) & 0xFF,
            (htonl(ipv4_packet->destination_ip)) & 0xFF,
            is_lan_ip(ntohl(ipv4_packet->destination_ip)) ? "lan" : "wan",
            ntohs(ipv4_packet->total_length),
            ipv4_packet->protocol
        );
    }

    bool from_lan = is_lan_ip(ntohl(ipv4_packet->source_ip));
    bool to_me = (ipv4_packet->destination_ip == my_ipv4_lan_ip || ipv4_packet->destination_ip == my_ipv4_wan_ip);

    // [3] NAT 및 라우팅 판단 (가장 중요한 분기점)
    if (from_lan && !is_lan_ip(ntohl(ipv4_packet->destination_ip))) {
        // CASE A: 내부 -> 외부 (Outbound NAT)
        nat_outbound_handler(ipv4_packet);
    } 
    else if (!from_lan && to_me) {
        // CASE B: 외부 -> 내부 (Inbound NAT 조회)
        // 여기서 NAT 장부에 있는 포트라면 'to_me'라도 가로채서 배달해야 함
        if (nat_inbound_handler(ipv4_packet)) {
            // NAT 배달 성공 시, 목적지가 노트북 IP로 바뀌었으므로 
            // 더 이상 'to_me'가 아님 -> 아래 [4]를 건너뛰고 포워딩으로 진행
        } else {
            // NAT 장부에 없으면 진짜 라우터 자신에게 온 패킷
            my_packet_handler(ipv4_packet);
            return 0; // 내가 처리했으므로 종료
        }
    }
    else if (to_me) {
        // CASE C: 내부에서 라우터 자신(10.0.0.1)을 부르는 경우
        my_packet_handler(ipv4_packet);
        return 0;
    }

    // checksum 계산
    ipv4_packet->header_checksum = 0;
    ipv4_packet->header_checksum = calculate_checksum(
        (uint16_t*)ipv4_packet, (ipv4_packet->version_ihl & 0x0F) * 4);

    // if(debug_mode_packet_read){
    //     printf("0x%04x\n", ntohs(ipv4_packet->header_checksum));
    // }

    struct ROUTE_ENTRY route = routing_table_find(ipv4_packet->destination_ip);

    if (route.gateway == 0) {
        return ipv4_packet->destination_ip;
    }

    return route.gateway;
}



uint32_t arp_read_handler(char* buffer){
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    uint32_t dest_ip = 0;

    // if(debug_mode_packet_read){
    //     printf("[packet_read] [arp] : %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
    //     arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5],
    //     arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
    // }

    bool is_request_for_lan = (memcmp(arp->tpa, (uint8_t*)&my_ipv4_lan_ip, 4) == 0);

    if(arp->oper == htons(1) &&
            (memcmp(arp->tpa, (uint8_t*)&my_ipv4_lan_ip, 4) == 0 
            || memcmp(arp->tpa, (uint8_t*)&my_ipv4_wan_ip, 4) == 0)){
        // ARP 요청인 경우 (내 IP로 온 경우)
        
        dest_ip = *(uint32_t*)arp->spa; // 요청한 쪽의 IP 주소
        arp->oper = htons(2); // 응답으로 변경

        memcpy(arp->tha, arp->sha, 6); // 대상 MAC 주소에 송신자 MAC 주소 복사
        memcpy(arp->tpa, arp->spa, 4); // 대상 IP 주소

        if(is_request_for_lan){
            // LAN에서 온 요청이면 -> 내 LAN 정보로 답장
            memcpy(arp->sha, mac_lan.mac, 6);
            memcpy(arp->spa, (uint8_t*)&my_ipv4_lan_ip, 4);
        } else {
            // WAN에서 온 요청이면 -> 내 WAN 정보로 답장
            memcpy(arp->sha, mac_wan.mac, 6);
            memcpy(arp->spa, (uint8_t*)&my_ipv4_wan_ip, 4);
        }
    }
 
    return dest_ip;
}

// void ipv6_read_handler(char* buffer){
//     return;
// }