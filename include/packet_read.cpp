#include <iostream>

#include <cstring>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "./common.h"
#include "./packets.h"
#include "./router_info.h"
#include "./packet_read.h"
#include "./route.h"

bool debug_mode_packet_read = true;

extern MAC_ADDRESS mac_lan;
extern MAC_ADDRESS mac_wan;

extern uint32_t my_ipv4_lan_ip;
extern uint32_t my_ipv4_wan_ip;

bool my_packet_handler(struct IPV4_HEADER* ipv4_packet){
    // 내 패킷 도착함

    // 마스크 사용해서 내부망인지 외부망인지 구분
    // 일단 icmp 기능만 구현
    uint32_t dest_ip = ipv4_packet->destination_ip;
    
    uint32_t lan_ip = inet_addr("10.0.0.1");      // 기준이 되는 내 LAN IP
    uint32_t netmask = inet_addr("255.255.255.0"); // 서브넷 마스크

    if(ipv4_packet->protocol == 1){ // ICMP
        // ICMP 패킷 처리
        struct ICMP_HEADER* icmp_packet = reinterpret_cast<struct ICMP_HEADER*>(
            (char*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4
        );

        if(debug_mode_packet_read){
            printf("ICMP Packet Type: %0x, Code: %0x\n", icmp_packet->type, icmp_packet->code);
        }

        if(icmp_packet->type == 8){ // 응답 요청
            icmp_packet->type = 0; // 응답으로 변경

            // checksum 재계산
            icmp_packet->checksum = 0;
            icmp_packet->checksum = calculate_checksum(
                (uint16_t*)icmp_packet, ntohs(ipv4_packet->total_length) - (ipv4_packet->version_ihl & 0x0F) * 4);

            if(debug_mode_packet_read){
                printf("ICMP packet received and Echo Request processed.\n");
            }
            return true;
        }

        // if(debug_mode_packet_read)
        //     printf("ICMP packet received and no action taken.\n");
        
        return false;
        
    }

    // NAT 처리
    if(dest_ip & netmask == lan_ip & netmask){
        // LAN
    }
    else {
        // WAN

    }

}

uint32_t ipv4_read_handler(char* buffer){
    struct IPV4_HEADER *ipv4_packet = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    if(ipv4_packet->time_to_live <= 1){ // TTL 만료 시 패킷 드롭
        if(debug_mode_packet_read){
            printf("TTL expired, dropping packet\n");
        }
        return 0;
    }

    // if(debug_mode_packet_read) {
    // // 보기 좋게 IP 문자열로 변환
    // struct in_addr dest, my_lan, my_wan;
    // dest.s_addr = ipv4_packet->destination_ip;
    // my_lan.s_addr = my_ipv4_lan_ip;
    // my_wan.s_addr = my_ipv4_wan_ip;

    // printf("[Debug] Packet Dest: %s | My LAN: %s | My WAN: %s\n", 
    //        inet_ntoa(dest), inet_ntoa(my_lan), inet_ntoa(my_wan));
    
    // // 혹시 모르니 Hex 값도 비교 (바이트 순서 확인용)
    // printf("[Hex]   Dest: 0x%08X   | LAN: 0x%08X   | WAN: 0x%08X\n", 
    //        ipv4_packet->destination_ip, my_ipv4_lan_ip, my_ipv4_wan_ip);
    // }

    if(ipv4_packet->destination_ip == my_ipv4_lan_ip || ipv4_packet->destination_ip == my_ipv4_wan_ip){
        // 내 패킷 도착
        if(debug_mode_packet_read){
            printf("packet is for this router.\n");
        }
        my_packet_handler(ipv4_packet);
    }
    else { // 내 패킷 아니므로 TTL 감소만
        // if(debug_mode_packet_read)
        //     printf("packet is for another destination.\n");
        ipv4_packet->time_to_live--;
    }

    // checksum 계산
    ipv4_packet->header_checksum = 0;
    ipv4_packet->header_checksum = calculate_checksum(
        (uint16_t*)ipv4_packet, ipv4_packet->version_ihl * 4);

    // if(debug_mode_packet_read){
    //     printf("0x%04x\n", ntohs(ipv4_packet->header_checksum));
    // }

    struct ROUTE_ENTRY route = routing_table_find(ipv4_packet->destination_ip);
    return route.gateway;
}

struct ARP_HEADER arp_read_handler(char* buffer){
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    
    if(debug_mode_packet_read){
        printf("[arp] : %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5],
        arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
    }

    return *arp;
}

// void ipv6_read_handler(char* buffer){
//     return;
// }