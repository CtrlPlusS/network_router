#include <iostream>
#include <cerrno>
#include <system_error>
#include <string>

#include <arpa/inet.h>

#include "./common.h"
#include "./packets.h"

extern bool debug_mode_common;

using namespace std;

//jsdoc형식으로
/**
* @brief Print error message corresponding to errno
* @param header 메시지 앞에 출력할 헤더 문자열
* @return errno 값
* @note Uses std::error_code to get the error message
*/
int print_errno_message(const string& header){
    error_code ec(errno, generic_category());
    cerr << header << ec.message() << endl;

    return ec.value();
}

/**
* @brief Print Ethernet and ARP packet information from buffer
* @param buffer 패킷 데이터가 담긴 버퍼
 */
void print_packet_info(char* msg, char* buffer) {

    printf("%s\n", msg);
    struct ETH_HEADER *eth = reinterpret_cast<struct ETH_HEADER*>(buffer);
    uint16_t ethertype = ntohs(eth->ethertype);

    cout << "\n========================================" << endl;
    cout << " [Layer 2] Ethernet Header" << endl;
    cout << "========================================" << endl;
    
    printf("Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
        eth->source_mac[0], eth->source_mac[1], eth->source_mac[2],
        eth->source_mac[3], eth->source_mac[4], eth->source_mac[5]);
    
    printf("Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
        eth->destination_mac[0], eth->destination_mac[1], eth->destination_mac[2],
        eth->destination_mac[3], eth->destination_mac[4], eth->destination_mac[5]);
    
    printf("EtherType       : 0x%04X ", ethertype);

    if (ethertype == ETH_HEADER_CONSTANTS::ETH_P_ARP) {
        cout << "(ARP)" << endl;
        struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
        
        cout << "\n   [Layer 2.5] ARP Header" << endl;
        cout << "   ----------------------" << endl;
        
        printf("   Sender MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
            arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
        printf("   Sender IP  : %d.%d.%d.%d\n",
            arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
        
        printf("   Target MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
            arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
        printf("   Target IP  : %d.%d.%d.%d\n",
            arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
            
        uint16_t oper = ntohs(arp->oper);
        printf("   Operation  : %s (%d)\n", (oper == 1 ? "Request" : (oper == 2 ? "Reply" : "Unknown")), oper);

    } else if (ethertype == ETH_HEADER_CONSTANTS::ETH_P_IPV4) {
        cout << "(IPv4)" << endl;
        struct IPV4_HEADER *ip = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));
        
        // IP Header Length (IHL) 계산 (4바이트 단위)
        int ip_header_len = (ip->version_ihl & 0x0F) * 4;
        
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->source_ip), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->destination_ip), dst_ip, INET_ADDRSTRLEN);

        cout << "\n   [Layer 3] IPv4 Header" << endl;
        cout << "   ---------------------" << endl;
        printf("   Source IP      : %s\n", src_ip);
        printf("   Destination IP : %s\n", dst_ip);
        printf("   Protocol       : %d ", ip->protocol);
        printf("   TTL            : %d\n", ip->time_to_live);
        printf("   Total Length   : %d bytes\n", ntohs(ip->total_length));

        // L4 헤더 포인터 계산 (Ethernet 헤더 + IP 헤더 길이만큼 이동)
        uint8_t* l4_ptr = (uint8_t*)buffer + sizeof(struct ETH_HEADER) + ip_header_len;

        if (ip->protocol == IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL) {
            struct TCP_HEADER *tcp = reinterpret_cast<struct TCP_HEADER*>(l4_ptr);
            cout << "\n      [Layer 4] TCP Header" << endl;
            cout << "      --------------------" << endl;
            printf("      Source Port      : %d\n", ntohs(tcp->source_port));
            printf("      Destination Port : %d\n", ntohs(tcp->destination_port));
            printf("      Seq Number       : %u\n", ntohl(tcp->sequence_number));
            printf("      Ack Number       : %u\n", ntohl(tcp->acknowledgment_number));
            
            // Flags 파싱 (Data offset 뒤에 있는 control bits)
            uint16_t flags = ntohs(tcp->data_offset_reserved_control) & 0x003F;
            printf("      Flags            : [ ");
            if (flags & 0x02) printf("SYN ");
            if (flags & 0x10) printf("ACK ");
            if (flags & 0x01) printf("FIN ");
            if (flags & 0x04) printf("RST ");
            if (flags & 0x08) printf("PSH ");
            if (flags & 0x20) printf("URG ");
            printf("]\n");

        } else if (ip->protocol == IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL) {
            struct UDP_HEADER *udp = reinterpret_cast<struct UDP_HEADER*>(l4_ptr);
            cout << "\n      [Layer 4] UDP Header" << endl;
            cout << "      --------------------" << endl;
            printf("      Source Port      : %d\n", ntohs(udp->source_port));
            printf("      Destination Port : %d\n", ntohs(udp->destination_port));
            printf("      Length           : %d\n", ntohs(udp->length));

        } else if (ip->protocol == IPV4_HEADER_PROTOCOL_CONSTANTS::ICMP_PROTOCOL) {
            struct ICMP_HEADER *icmp = reinterpret_cast<struct ICMP_HEADER*>(l4_ptr);
            cout << "\n      [Layer 4] ICMP Header" << endl;
            cout << "      ---------------------" << endl;
            printf("      Type : %d", icmp->type);
            if(icmp->type == 8) printf(" (Echo Request)\n");
            else if(icmp->type == 0) printf(" (Echo Reply)\n");
            else printf("\n");
            
            printf("      Code : %d\n", icmp->code);
        }
    } else {
        printf("(Unknown: 0x%04X)\n", ethertype);
    }
    cout << "========================================\n" << endl;
}


uint32_t sum_1s_complement(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len > 0) {
        sum += *(uint8_t *)buf; 
    }
    return sum;
}

uint16_t finalize_checksum(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// IP 헤더 체크섬 계산
uint16_t calculate_checksum(uint16_t *addr, int len) {
    uint32_t sum = sum_1s_complement(addr, len);
    return finalize_checksum(sum);
}

// UDP 체크섬 계산 (가상 헤더 포함)
void udp_calculate_checksum(struct UDP_HEADER *udp, struct IPV4_HEADER *ip) {
    udp->checksum = 0;

    uint32_t sum = 0;
    
    uint16_t *src_dst = (uint16_t *)&ip->source_ip;
    for(int i=0; i<4; i++) sum += src_dst[i];

    sum += htons(ip->protocol); // 17
    sum += udp->length;         // UDP Length

    sum += sum_1s_complement((uint16_t *)udp, ntohs(udp->length));

    udp->checksum = finalize_checksum(sum);
    
    if (udp->checksum == 0) udp->checksum = 0xFFFF;
}

// TCP 체크섬 계산 (가상 헤더 포함)
void tcp_calculate_checksum(struct TCP_HEADER *tcp, struct IPV4_HEADER *ip) {
    tcp->checksum = 0;

    uint32_t sum = 0;
    uint16_t *src_dst = (uint16_t *)&ip->source_ip;
    for(int i=0; i<4; i++) sum += src_dst[i];

    sum += htons(ip->protocol); // 6
    uint16_t tcp_len = ntohs(ip->total_length) - (ip->version_ihl & 0x0F) * 4;
    sum += htons(tcp_len);

    sum += sum_1s_complement((uint16_t *)tcp, tcp_len);

    tcp->checksum = finalize_checksum(sum);
}

void icmp_calculate_checksum(struct ICMP_HEADER* icmp_packet, struct IPV4_HEADER* ipv4_packet){
    // checksum 재계산
        icmp_packet->checksum = 0; // 1. 먼저 0으로 초기화 (필수)
        icmp_packet->checksum = calculate_checksum(
            (uint16_t*)icmp_packet, // 2. ICMP 헤더 시작 주소
            ntohs(ipv4_packet->total_length) - (ipv4_packet->version_ihl & 0x0F) * 4 // 3. IP 헤더를 뺀 순수 ICMP 길이
        );
}