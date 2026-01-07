#include <iostream>

#include "./route.cpp"
#include "./packets.h"

extern bool debug_mode;

uint8_t my_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};

void ipv4_send_handler(struct ETH_HEADER* eth_header, struct IPV4_HEADER* ipv4_packet){
    /*
    void ipv4_update_checksum_incremental(struct iphdr* ip_header) {
    // 1. 기존 체크섬 값을 32비트로 읽어옴 (Carry 처리를 위해)
    uint32_t sum = ip_header->check; // Network Byte Order 그대로 사용

    // 2. TTL 변경 반영
    // TTL은 16비트 워드의 상위 바이트에 위치하므로, 
    // TTL - 1은 16비트 정수에서 0x0100을 빼는 것과 같음.
    // 데이터 합이 줄었으니, 반전된 체크섬은 반대로 0x0100을 더해줌.
    sum += htons(0x0100); 

    // 3. 캐리(Carry) 처리 (Folding)
    // 덧셈 결과가 0xFFFF를 넘어가면 다시 더해줌
    sum = (sum & 0xFFFF) + (sum >> 16);
    
    // 4. 저장
    ip_header->check = (uint16_t)sum;
    }
    */

    if(debug_mode){
        printf("Checksum before: 0x%04x -> ", ntohs(ipv4_packet->header_checksum));
    }

    // TTL 감소, checksum 재계산
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

    if(debug_mode){
        printf("Checksum after: 0x%04x\n", ntohs(ipv4_packet->header_checksum));
    }
    
    
}

int forward_ipv4_packet(int sock_raw, struct ETH_HEADER* eth_header, struct IPV4_HEADER* ipv4_packet){
    uint8_t target_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 02}; // 나중에 ARP 테이블에서 조회
    struct ROUTE_ENTRY route = srouting_table_find(ipv4_packet->destination_ip);

    memcpy(eth_header->source_mac, my_mac, 6);
    memcpy(eth_header->destination_mac, target_mac, 6);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(route.interface);
    sll.sll_protocol = htons(ETH_HEADER_CONSTANTS::ETH_P_IP);

    if(sendto(sock_raw, 
    }
}