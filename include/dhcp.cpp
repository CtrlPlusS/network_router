#include <arpa/inet.h>
#include <utility>
#include <time.h>
#include <cstring>
#include <cstdio>
#include <map>

#include "./packet_send.h"
#include "./packets.h"
#include "./router_info.h"
#include "./common.h"

void init_dhcp_table(){
    auto& info = router_info::instance();
    info.allocated_dhcp_ip_table = std::vector<std::pair<bool, time_t>>(256);
    info.static_ip_table.clear();
    // std::fill(router_info::instance().allocated_dhcp_ip_table.begin(),
    //          router_info::instance().allocated_dhcp_ip_table.end(),
    //          default_table);
}

uint16_t allocate_ip_num(std::string mac){
    auto& info = router_info::instance();

    if(info.debug_mode_dhcp){
        PRINT_LOG_MESSAGE("[dhcp] mac in - %s\n", mac.data());
    }
    
    auto it = info.static_ip_table.find(mac);
    if(it != info.static_ip_table.end()){
        if(info.debug_mode_dhcp) {
            PRINT_LOG_MESSAGE("[dhcp] STATIC IP FOUND! MAC: %s -> Num: %d\n", mac.c_str(), it->second);
        }
        return it->second;        
    }
    if(info.debug_mode_dhcp) {
        PRINT_LOG_MESSAGE("[dhcp] Static IP NOT found for MAC: %s. Total table size: %lu\n", 
                           mac.c_str(), info.static_ip_table.size());
    }

    for(int i = info.dhcp_ip_start_num; i <= info.dhcp_ip_end_num; ++i){
        if(!info.allocated_dhcp_ip_table[i - info.dhcp_ip_start_num].first){
            return i;
        }
    }
    return 256;
}

void refresh_dhcp_entries(){
    auto& info = router_info::instance();
    time_t now = time(NULL);

    for(auto it : info.allocated_dhcp_ip_table){
        if(it.first && it.second > now)
            it.first = false;
    }
}

int dhcp_discover_handler(char* buffer){
    auto& info = router_info::instance();

    struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>((uint8_t*)buffer);
    struct IPV4_HEADER* ipv4_packet = reinterpret_cast<IPV4_HEADER*>((uint8_t*)buffer + sizeof(struct ETH_HEADER));
    struct UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);
    struct DHCP_HEADER* dhcp_packet = reinterpret_cast<DHCP_HEADER*>((uint8_t*)udp_packet + sizeof(struct UDP_HEADER));

    char mac_buf[18];
    snprintf(mac_buf, sizeof(mac_buf), "%02X:%02X:%02X:%02X:%02X:%02X",
         dhcp_packet->chaddr[0], dhcp_packet->chaddr[1], dhcp_packet->chaddr[2],
         dhcp_packet->chaddr[3], dhcp_packet->chaddr[4], dhcp_packet->chaddr[5]);
    std::string mac_str = mac_buf;    

    uint16_t allocated_ip_num = allocate_ip_num(mac_str);

    if(info.debug_mode_dhcp){
        PRINT_LOG_MESSAGE("[dhcp] discover packet discovered. offering 10.0.0.%d\n", allocated_ip_num);
    }

    if(allocated_ip_num >= 255)
        return 0;
    dhcp_packet->op = 2;
    dhcp_packet->hops = 0;
    dhcp_packet->secs = 0;
    dhcp_packet->ciaddr = inet_addr("0.0.0.0");
    
    dhcp_packet->yiaddr = (info.my_ipv4_lan_ip & 0x00FFFFFF) | (allocated_ip_num << 24);
    dhcp_packet->siaddr = info.my_ipv4_lan_ip;
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
    memcpy(opt, &info.my_ipv4_lan_ip, 4);
    opt += 4;

    // Option 6: DNS (8.8.8.8)
    *opt++ = 6; *opt++ = 4;
    memcpy(opt, &info.dhcp_dns_server, 4);
    opt += 4;

    // Option 54: Server ID (10.0.0.1) - 필수
    *opt++ = 54; *opt++ = 4;
    memcpy(opt, &info.my_ipv4_lan_ip, 4);
    opt += 4;

    *opt++ = 51; *opt++ = 4;
    uint32_t offering_time = htonl(info.dhcp_offering_time); 
    memcpy(opt, &offering_time, 4);
    opt += 4;   

    // Option 255: End
    *opt++ = 255;

    udp_packet->source_port = htons(67);
    udp_packet->destination_port = htons(68);

    uint16_t udp_total_length = 8 + (opt - (uint8_t*)dhcp_packet);
    udp_packet->length = htons(udp_total_length);

    ipv4_packet->total_length = htons(20 +  udp_total_length);
    ipv4_packet->flags_fragment_offset &= 0b0000'0000'0000'0111;
    ipv4_packet->time_to_live = 64;
    ipv4_packet->protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL;
    ipv4_packet->header_checksum = 0;
    ipv4_packet->source_ip = info.my_ipv4_lan_ip;
    ipv4_packet->destination_ip = inet_addr("255.255.255.255");
    ipv4_packet->header_checksum = calculate_checksum((uint16_t*)ipv4_packet, 20);

    memcpy((MAC_ADDRESS*)eth_packet->source_mac, &info.my_mac_lan, 6);
    memset(eth_packet->destination_mac, 0xFF, 6);
    eth_packet->ethertype = htons(ETH_HEADER_CONSTANTS::ETH_P_IPV4);

    udp_calculate_checksum(udp_packet, ipv4_packet);

    return (uint8_t*)opt - (uint8_t*)buffer;
}

int dhcp_request_handler(char* buffer){
    auto& info = router_info::instance();

    struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>((uint8_t*)buffer);
    struct IPV4_HEADER* ipv4_packet = reinterpret_cast<IPV4_HEADER*>((uint8_t*)buffer + sizeof(struct ETH_HEADER));
    struct UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);
    struct DHCP_HEADER* dhcp_packet = reinterpret_cast<DHCP_HEADER*>((uint8_t*)udp_packet + sizeof(struct UDP_HEADER));

    // 1. mac 주소 확인해서 FF:FF:FF:FF:FF:FF이면 
    // 1-1. ciaddr 확인 후 주소 있으면 갱신. (갱신)
    // 1-2. ciaddr 없으면 옵션 값 확인 후 반환 (신규주소)

    // 2. mac 주소가 공유기 mac(lan)이면
    // 2-1. ciaddr 확인 후 갱신. (갱신)

    uint16_t allocated_ip_num = 0; // 못 찾으면 0
    bool is_renewal = (dhcp_packet->ciaddr != 0);
    bool is_broadcast = ntohs(dhcp_packet->flags) & 0x8000;
    bool is_nak = false;

    if(info.debug_mode_dhcp){
        PRINT_LOG_MESSAGE("[dhcp] dhcp in. flag is %x(raw)\n", dhcp_packet->flags);
    }
    
    if(is_renewal){
        allocated_ip_num = ntohl(dhcp_packet->ciaddr) & 0xFF;
    }
    else{
        uint8_t* option_ptr = dhcp_packet->options;

        while(*option_ptr != 255 && (option_ptr - dhcp_packet->options) < 300) { // End Option(255) 만날 때까지 또는 3500바이트 초과까지(255 없는 경우)
            if(*option_ptr == 50){
                allocated_ip_num = *(option_ptr + 5);
                break;
            }
            else
                option_ptr += (*option_ptr) == 0 ? 1 : (*(option_ptr + 1) + 2);
        }
    }

    if(info.debug_mode_dhcp){
        PRINT_LOG_MESSAGE("[dhcp] dhcp in. requesting ip is  10.0.0.%d\n", allocated_ip_num);
    }

    if (allocated_ip_num < 256 && (is_renewal || !info.allocated_dhcp_ip_table[allocated_ip_num].first)) {
        // request가 기존에 안쓰던거임 -> 그냥 바로 할당해줌
        info.allocated_dhcp_ip_table[allocated_ip_num].first = true;
        info.allocated_dhcp_ip_table[allocated_ip_num].second = time(NULL) + info.dhcp_offering_time;    
    }
    else{
        // 기존에 쓰던 ip임 -> nak
        is_nak = true;
    }

    dhcp_packet->op = 2;
    dhcp_packet->hops = 0;
    dhcp_packet->secs = 0;

    dhcp_packet->yiaddr = (info.my_ipv4_lan_ip & 0x00FFFFFF) | (allocated_ip_num << 24);
    dhcp_packet->siaddr = info.my_ipv4_lan_ip;
    dhcp_packet->giaddr = inet_addr("0.0.0.0");
    dhcp_packet->magic_cookie = htonl(0x63825363);

    uint8_t* opt = reinterpret_cast<uint8_t*>((uint8_t*)dhcp_packet->options);
    *opt++ = 53; *opt++ = 1; *opt++ = is_nak ? 6 : 5; 

    // Option 54: Server ID (10.0.0.1) - 필수
    *opt++ = 54; *opt++ = 4;
    memcpy(opt, &info.my_ipv4_lan_ip, 4);
    opt += 4;

    if(!is_nak){
        // Option 1: Subnet Mask (255.255.255.0)
        *opt++ = 1; *opt++ = 4;
        *opt++ = 255; *opt++ = 255; *opt++ = 255; *opt++ = 0;

        // Option 3: Router (10.0.0.1)
        *opt++ = 3; *opt++ = 4;
        memcpy(opt, &info.my_ipv4_lan_ip, 4);
        opt += 4;

        // Option 6: DNS (8.8.8.8)
        *opt++ = 6; *opt++ = 4;
        *(uint32_t*)opt = info.dhcp_dns_server;
        memcpy(opt, &info.dhcp_dns_server, 4);
        opt += 4;

        *opt++ = 51; *opt++ = 4;
        uint32_t offering_time = htonl(info.dhcp_offering_time); 
        memcpy(opt, &offering_time, 4);
        opt += 4;   
    }

    // Option 255: End
    *opt++ = 255;

    while ((opt - (uint8_t*)dhcp_packet) < 300) {
        *opt++ = 0; 
    }

    udp_packet->source_port = htons(67);
    udp_packet->destination_port = htons(68);

    uint16_t udp_total_length = 8 + (opt - (uint8_t*)dhcp_packet);
    udp_packet->length = htons(udp_total_length);

    ipv4_packet->total_length = htons(20 +  udp_total_length);
    ipv4_packet->flags_fragment_offset &= 0b0000'0000'0000'0111;
    ipv4_packet->time_to_live = 64;
    ipv4_packet->protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::UDP_PROTOCOL;
    ipv4_packet->header_checksum = 0;
    if(is_renewal && !is_broadcast){
        ipv4_packet->destination_ip = dhcp_packet->ciaddr;
    }
    else{
        ipv4_packet->destination_ip = inet_addr("255.255.255.255");
    }
    ipv4_packet->source_ip = info.my_ipv4_lan_ip;
    ipv4_packet->header_checksum = calculate_checksum((uint16_t*)ipv4_packet, 20);

    memcpy(eth_packet->destination_mac, eth_packet->source_mac, 6);
    // if(is_renewal && !is_broadcast){
    //     memcpy(eth_packet->destination_mac, eth_packet->source_mac, 6);
    // }
    // else{
    //     memset(eth_packet->destination_mac, 0xFF, 6);
    // }

    info.arp_table[dhcp_packet->yiaddr] = *(MAC_ADDRESS*)eth_packet->source_mac;
    memcpy((MAC_ADDRESS*)eth_packet->source_mac, &info.my_mac_lan, 6);
    eth_packet->ethertype = htons(ETH_HEADER_CONSTANTS::ETH_P_IPV4);

    udp_calculate_checksum(udp_packet, ipv4_packet);

    if(info.debug_mode_dhcp){
        PRINT_LOG_MESSAGE("[dhcp] request packet detected. ack packet 10.0.0.%d(%d) sent to (ip : %d.%d.%d.%d. mac : %02X:%02X:%02X:%02X:%02X:%02X)\n", 
                allocated_ip_num,
                info.dhcp_offering_time, 
                (htonl(ipv4_packet->destination_ip) >> 24) & 0xFF,
                (htonl(ipv4_packet->destination_ip) >> 16) & 0xFF,
                (htonl(ipv4_packet->destination_ip) >>  8) & 0xFF,
                htonl(ipv4_packet->destination_ip) & 0xFF,
                eth_packet->destination_mac[0],
                eth_packet->destination_mac[1],
                eth_packet->destination_mac[2],
                eth_packet->destination_mac[3],
                eth_packet->destination_mac[4],
                eth_packet->destination_mac[5]
            );
    }

    return (uint8_t*)opt - (uint8_t*)buffer;
}

int dhcp_read_handler(char *buffer){
    // dhcp_header* 정의
    // struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>((uint8_t*)buffer);
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
