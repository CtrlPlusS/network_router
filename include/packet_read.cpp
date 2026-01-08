#include <iostream>
#include <arpa/inet.h>

#include "./packet_read.h"
#include "./route.h"

extern bool debug_mode;

uint32_t ipv4_read_handler(char* buffer){
    struct IPV4_HEADER *ipv4_packet = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    if(ipv4_packet->time_to_live <= 1){ // TTL 만료 시 패킷 드롭
        if(debug_mode){
            printf("TTL expired, dropping packet\n");
        }
        return 0;
    }

    if(ipv4_packet->destination_ip == inet_addr("192.168.0.11")){ // 라우터 자신의 IP 주소
        if(debug_mode){
            printf("Packet destined for router, dropping packet\n");
        }
        return 0; // 라우터 자신으로 향하는 패킷 드롭
    }

    ipv4_packet->time_to_live--;
    ipv4_packet->header_checksum = 0;

    // checksum 계산
    uint16_t *entries = (uint16_t*)(ipv4_packet);
    uint32_t checksum = 0;

    uint8_t count = (ipv4_packet->version_ihl & 0x0F) * 2; // IHL 필드로 헤더 길이(16비트 단위) 계산
    while(count--){
        checksum += *entries++;
    }

    while(checksum >> 16){
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    ipv4_packet->header_checksum = (uint16_t)(~checksum);

    // if(debug_mode){
    //     printf("0x%04x\n", ntohs(ipv4_packet->header_checksum));
    // }

    struct ROUTE_ENTRY route = routing_table_find(ipv4_packet->destination_ip);
    return route.gateway;
}

struct ARP_HEADER arp_read_handler(char* buffer){
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    
    if(debug_mode){
        printf("[arp] : %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5],
        arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
    }

    return *arp;
}

// void ipv6_read_handler(char* buffer){
//     return;
// }