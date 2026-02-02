// 패킷 읽고 처리까지. 
// 전송은 packet_send.cpp에서 처리

#include <climits>
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
// #include "./packet_read.h"
#include "./route.h"
#include "./firewall.h"
#include "./dhcp.h"
#include "./packet_send.h"

void my_packet_icmp_handler(struct IPV4_HEADER* ipv4_packet){
    struct ICMP_HEADER* icmp_packet = reinterpret_cast<struct ICMP_HEADER*>(
            (char*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
        );

    if(icmp_packet->type == 8){ // 응답 요청
        icmp_packet->type = 0; // 응답으로 변경

        icmp_calculate_checksum(icmp_packet, ipv4_packet);
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

bool ipv4_packet_drop_check(IPV4_HEADER* ipv4_packet){
    auto& info = router_info::instance();
    // 루프백 패킷 드롭
    if((ntohl(ipv4_packet->destination_ip) >> 24) == 127)
        return true;

    // 멀티캐스트 패킷 드롭
    if((ntohl(ipv4_packet->destination_ip) & 0xF0000000) == 0xE0000000)
        return true;

    if(ipv4_packet->source_ip == info.my_ipv4_wan_ip)
        return true;

    if(ipv4_packet->source_ip == ipv4_packet->destination_ip)
        return true;

    if(ipv4_packet->time_to_live <= 1){ // TTL 만료 시 패킷 드롭
        return true;
    }

    uint8_t firewall_check;
    switch(ipv4_packet->protocol){
        case IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL:{
            firewall_check = firewall_icmp_packet_find(ipv4_packet);
            break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL:{
            firewall_check = firewall_tcp_packet_find(ipv4_packet);
            break;
        }

        case IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL:{
            firewall_check = firewall_udp_packet_find(ipv4_packet);
            break;
        }

        default:
            firewall_check = false;
    }

    switch(firewall_check){
        case FIREWALL_ACTION_CONSTANTS::REJECT:{
            if(info.debug_mode_security){
                PRINT_LOG_MESSAGE("[security] packet %d.%d.%d.%d -> %d.%d.%d.%d rejected.\n",
                    (htonl(ipv4_packet->source_ip) >> 24) & 0xFF,
                    (htonl(ipv4_packet->source_ip) >> 16) & 0xFF,
                    (htonl(ipv4_packet->source_ip) >>  8) & 0xFF,
                        htonl(ipv4_packet->source_ip)     & 0xFF,

                    (htonl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                    (htonl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                    (htonl(ipv4_packet->destination_ip) >>  8) & 0xFF,
                        htonl(ipv4_packet->destination_ip)     & 0xFF
                );
            }
        }
        
        case FIREWALL_ACTION_CONSTANTS::DROP:{
            return true;
        }

        default:;
    }

    return false;
}

uint32_t ipv4_read_handler(char* buffer, int sock, int if_index){
    auto& info = router_info::instance();
    struct IPV4_HEADER *ipv4_packet = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    if(ipv4_packet_drop_check(ipv4_packet))
        return 0;

    // udp이고 destination_port가 67인것들은 dhcp처리
    if(ipv4_packet->protocol == IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL){
        struct UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);
        if(ntohs(udp_packet->destination_port) == 67){
            int packet_len = dhcp_read_handler(buffer);
            if(packet_len == 0)
                return 0;
            
            dhcp_send_handler(sock, buffer, packet_len, if_index);
            return 0;
        }
    }

    bool from_lan = is_lan_ip(ntohl(ipv4_packet->source_ip));
    bool to_me = (ipv4_packet->destination_ip == info.my_ipv4_lan_ip || ipv4_packet->destination_ip == info.my_ipv4_wan_ip);

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

uint32_t arp_read_handler(char* buffer, int sock, int if_index){
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    auto& info = router_info::instance();
    uint32_t dest_ip = 0;

    bool is_request_for_lan = (memcmp(arp->tpa, (uint8_t*)&info.my_ipv4_lan_ip, 4) == 0);

    switch(ntohs(arp->oper)){
        case 1:{ // request
            if((memcmp(arp->tpa, (uint8_t*)&info.my_ipv4_lan_ip, 4) == 0 
            || memcmp(arp->tpa, (uint8_t*)&info.my_ipv4_wan_ip, 4) == 0)){
                // ARP 요청인 경우 (내 IP로 온 경우)
                
                dest_ip = *(uint32_t*)arp->spa; // 요청한 쪽의 IP 주소
                arp->oper = htons(2); // 응답으로 변경

                memcpy(arp->tha, arp->sha, 6); // 대상 MAC 주소에 송신자 MAC 주소 복사
                memcpy(arp->tpa, arp->spa, 4); // 대상 IP 주소

                if(is_request_for_lan){
                    // LAN에서 온 요청이면 -> 내 LAN 정보로 답장
                    memcpy(arp->sha, info.my_mac_lan.mac, 6);
                    memcpy(arp->spa, (uint8_t*)&info.my_ipv4_lan_ip, 4);
                } else {
                    // WAN에서 온 요청이면 -> 내 WAN 정보로 답장
                    memcpy(arp->sha, info.my_mac_wan.mac, 6);
                    memcpy(arp->spa, (uint8_t*)&info.my_ipv4_wan_ip, 4);
                }
            }
            else{
                // 내 요청 아닌데 들어온거는 일단 arp테이블에 저장
                info.arp_table[*(uint32_t*)arp->spa] = *(struct MAC_ADDRESS*)arp->sha;
            }
            break;
        }
        case 2:{ // reply
            info.arp_table[*(uint32_t*)arp->spa] = *(struct MAC_ADDRESS*)arp->sha;
            // arp_table[*(uint32_t*)arp->tpa] = *(struct MAC_ADDRESS*)arp->tha;

            auto it = info.pending_packets.find(*(uint32_t*)arp->spa);
            if(it != info.pending_packets.end()){
                pending_packet_send_handler(it->second, sock, *(uint32_t*)arp->spa, if_index);
            }
            break;
        }

        default:{
            info.arp_table[*(uint32_t*)arp->spa] = *(struct MAC_ADDRESS*)arp->sha;
        }
    }

 
    return dest_ip;
}

// void ipv6_read_handler(char* buffer){
//     return;
// }