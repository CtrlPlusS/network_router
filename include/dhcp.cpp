#include <arpa/inet.h>
#include <utility>
#include <time.h>
#include <cstring>
#include <cstdio>

#include "./packets.h"
#include "./router_info.h"
#include "common.h"

std::pair<bool, time_t> allocated_ip_table[253];

extern struct MAC_ADDRESS mac_lan;

uint16_t last_ip_num; // 2 ~ 254

void init_dhcp_table(){
    memset(allocated_ip_table, 0, sizeof(std::pair<bool, time_t>) * 253);
    last_ip_num = 0;
}

uint16_t allocate_ip_num(){
    for(int i = 0; i < 253; ++i){
        int idx = (last_ip_num + i) % 253;
        if(!allocated_ip_table[idx].first){
            return idx + 2;
        }
    }
    return 256;
}

void cleanup_expired_dhcp_entries(){
    time_t now = time(NULL);
    for(int i = 1; i < 255; ++i){
        if(allocated_ip_table[i].first && allocated_ip_table[i].second > now){
            allocated_ip_table[i].first = false;
        }
    }
}

int dhcp_discover_handler(char* buffer){
    struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>((uint8_t*)buffer);
    struct IPV4_HEADER* ipv4_packet = reinterpret_cast<IPV4_HEADER*>((uint8_t*)buffer + sizeof(struct ETH_HEADER));
    struct UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);
    struct DHCP_HEADER* dhcp_packet = reinterpret_cast<DHCP_HEADER*>((uint8_t*)udp_packet + sizeof(struct UDP_HEADER));

    uint16_t allocated_ip_num = allocate_ip_num();
    if(allocated_ip_num >= 255)
        return 0;  
    dhcp_packet->op = 2;
    dhcp_packet->hops = 0;
    dhcp_packet->secs = 0;
    dhcp_packet->ciaddr = inet_addr("0.0.0.0");

    char ip_num_buffer[20];
    sprintf(ip_num_buffer, "10.0.0.%d", allocated_ip_num);
    dhcp_packet->yiaddr = inet_addr(ip_num_buffer);
    dhcp_packet->siaddr = inet_addr("10.0.0.1");
    dhcp_packet->giaddr = inet_addr("0.0.0.0");
    memset(dhcp_packet->sname, 0, 64);
    memset(dhcp_packet->file, 0, 128);
    dhcp_packet->magic_cookie = htonl(0x63825363);

    uint8_t* opt = reinterpret_cast<uint8_t*>((uint8_t*)dhcp_packet->options);
    *opt++ = 53; *opt++ = 1; *opt++ = 2; 

    // Option 1: Subnet Mask (255.255.255.0)
    *opt++ = 1; *opt++ = 4;
    *opt++ = 255; *opt++ = 255; *opt++ = 255; *opt++ = 0;

    // Option 3: Router (10.0.0.1)
    *opt++ = 3; *opt++ = 4;
    *(uint32_t*)opt = inet_addr("10.0.0.1"); opt += 4;

    // Option 6: DNS (8.8.8.8)
    *opt++ = 6; *opt++ = 4;
    *(uint32_t*)opt = inet_addr("8.8.8.8"); opt += 4;

    // Option 54: Server ID (10.0.0.1) - 필수
    *opt++ = 54; *opt++ = 4;
    *(uint32_t*)opt = inet_addr("10.0.0.1"); opt += 4;

    *opt++ = 51; *opt++ = 4;
    *(uint32_t*)opt = htonl(3600); opt += 4;   

    // Option 255: End
    *opt++ = 255;

    udp_packet->source_port = htons(67);
    udp_packet->destination_port = htons(68);

    uint16_t udp_total_length = 8 + (opt - (uint8_t*)dhcp_packet);
    udp_packet->length = htons(udp_total_length);
    udp_packet->checksum = 0;

    ipv4_packet->total_length = htons(20 +  udp_total_length);
    ipv4_packet->flags_fragment_offset &= 0b0000'0000'0000'0111;
    ipv4_packet->time_to_live = 64;
    ipv4_packet->protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL;
    ipv4_packet->header_checksum = 0;
    ipv4_packet->source_ip = inet_addr("10.0.0.1");
    ipv4_packet->destination_ip = inet_addr("255.255.255.255");
    ipv4_packet->header_checksum = calculate_checksum((uint16_t*)ipv4_packet, 20);

    memcpy((MAC_ADDRESS*)eth_packet->source_mac, &mac_lan, 6);
    memset(eth_packet->destination_mac, 0xFF, 6);
    eth_packet->ethertype = htons(ETH_HEADER_CONSTANTS::ETH_P_IPV4);

    return (uint8_t*)opt - (uint8_t*)buffer;
}

int dhcp_request_handler(char* buffer){
    struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>((uint8_t*)buffer);
    struct IPV4_HEADER* ipv4_packet = reinterpret_cast<IPV4_HEADER*>((uint8_t*)buffer + sizeof(struct ETH_HEADER));
    struct UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);
    struct DHCP_HEADER* dhcp_packet = reinterpret_cast<DHCP_HEADER*>((uint8_t*)udp_packet + sizeof(struct UDP_HEADER));

    uint8_t* requested_ip = dhcp_packet->options;
    while(*requested_ip != 50 && *requested_ip != 255){
        requested_ip++;
        requested_ip = requested_ip + *(requested_ip);
    }

    uint8_t requested_ip_num = *requested_ip;
    allocated_ip_table[requested_ip_num].first = true;
    allocated_ip_table[requested_ip_num].second = time(NULL) + 3600;

    dhcp_packet->op = 5;
    dhcp_packet->hops = 0;
    dhcp_packet->secs = 0;
    dhcp_packet->ciaddr = inet_addr("0.0.0.0");

    char ip_num_buffer[20];
    sprintf(ip_num_buffer, "10.0.0.%d", requested_ip_num);
    dhcp_packet->yiaddr = inet_addr(ip_num_buffer);
    dhcp_packet->siaddr = inet_addr("10.0.0.1");
    dhcp_packet->giaddr = inet_addr("0.0.0.0");
    memset(dhcp_packet->sname, 0, 64);
    memset(dhcp_packet->file, 0, 128);
    dhcp_packet->magic_cookie = htonl(0x63825363);

    uint8_t* opt = reinterpret_cast<uint8_t*>((uint8_t*)dhcp_packet->options);
    *opt++ = 53; *opt++ = 1; *opt++ = 2; 

    // Option 1: Subnet Mask (255.255.255.0)
    *opt++ = 1; *opt++ = 4;
    *opt++ = 255; *opt++ = 255; *opt++ = 255; *opt++ = 0;

    // Option 3: Router (10.0.0.1)
    *opt++ = 3; *opt++ = 4;
    *(uint32_t*)opt = inet_addr("10.0.0.1"); opt += 4;

    // Option 6: DNS (8.8.8.8)
    *opt++ = 6; *opt++ = 4;
    *(uint32_t*)opt = inet_addr("8.8.8.8"); opt += 4;

    // Option 54: Server ID (10.0.0.1) - 필수
    *opt++ = 54; *opt++ = 4;
    *(uint32_t*)opt = inet_addr("10.0.0.1"); opt += 4;

    *opt++ = 51; *opt++ = 4;
    *(uint32_t*)opt = htonl(3600); opt += 4;   

    // Option 255: End
    *opt++ = 255;

    udp_packet->source_port = htons(67);
    udp_packet->destination_port = htons(68);

    uint16_t udp_total_length = 8 + (opt - (uint8_t*)dhcp_packet);
    udp_packet->length = htons(udp_total_length);
    udp_packet->checksum = 0;

    ipv4_packet->total_length = htons(20 +  udp_total_length);
    ipv4_packet->flags_fragment_offset &= 0b0000'0000'0000'0111;
    ipv4_packet->time_to_live = 64;
    ipv4_packet->protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL;
    ipv4_packet->header_checksum = 0;
    ipv4_packet->source_ip = inet_addr("10.0.0.1");
    ipv4_packet->destination_ip = inet_addr("255.255.255.255");
    ipv4_packet->header_checksum = calculate_checksum((uint16_t*)ipv4_packet, 20);

    memcpy((MAC_ADDRESS*)eth_packet->source_mac, &mac_lan, 6);
    memset(eth_packet->destination_mac, 0xFF, 6);
    eth_packet->ethertype = htons(ETH_HEADER_CONSTANTS::ETH_P_IPV4);

    return (uint8_t*)opt - (uint8_t*)buffer;
}

int dhcp_read_handler(char *buffer){
    // dhcp_header* 정의
    struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>((uint8_t*)buffer);
    struct IPV4_HEADER* ipv4_packet = reinterpret_cast<IPV4_HEADER*>((uint8_t*)buffer + sizeof(struct ETH_HEADER));
    struct UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);
    struct DHCP_HEADER* dhcp_packet = reinterpret_cast<DHCP_HEADER*>((uint8_t*)udp_packet + sizeof(struct UDP_HEADER));

    uint8_t* opt = dhcp_packet->options + 2;

    // dhcp 옵션 확인 : discover offer request ack
    // discover : port 68번으로 offer
    // request : port 68번으로 ack
    switch(*opt){
        case 1:{ // discover   
            return dhcp_discover_handler(buffer); // 전체 길이 반환
            break;
        }

        case 3:{ // request
            return dhcp_request_handler(buffer); // 전체 길이 반환
            break;
        }

        default:{ // 2 : reply, 5 : ack
            return 0;
        }
    }

    // 라우터가 처리해야 하는거

    // Ethernet Dst MAC: FF:FF:FF:FF:FF:FF (L2 Broadcast)
    // IP Dst IP: 255.255.255.255 (L3 Broadcast)
    // DHCP Header yiaddr: 여기에 "너 10.0.0.2 써라" 하고 적어줍니다.
    // DHCP Header chaddr: 여기에 클라이언트의 MAC 주소를 그대로 복사해 넣어야, 클라이언트가 "아 내 거구나" 하고 알아챕니다.

    // offer : 보낸 라우터 쪽으로 broadcast로 보내줌
    // ack : 남은 ip번호 확인후 dhcp_header에 적어서 ack 발송
}
