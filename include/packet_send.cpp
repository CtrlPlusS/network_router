// #include <iostream>
#include <cstring>
#include <map>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
// #include <sys/socket.h>
// #include <netinet/in.h>

#include "./router_info.h"
#include "./packet_send.h"
#include "./common.h"
#include "./packets.h"

extern bool debug_mode_packet_send;

std::map<uint32_t, struct MAC_ADDRESS> arp_table;
extern struct MAC_ADDRESS mac_lan;
extern struct MAC_ADDRESS mac_wan;

void init_mac_address(){
    arp_table.clear();

    arp_table[inet_addr("192.168.0.1")] = {0x90, 0x9f, 0x33, 0xdf, 0x7b, 0x98}; // wlan0 MAC 주소
    arp_table[inet_addr("0.0.0.0")] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // 브로드캐스트 주소
    arp_table[inet_addr("10.0.0.2")] = {0x00, 0x2b, 0x67, 0xfe, 0x96, 0x4e}; // 노트북 MAC 주소 
}

/**
 * @brief IP 주소에 해당하는 MAC 주소를 반환합니다.
 * @param ip_address IP 주소
 * @return MAC 주소
 */
struct MAC_ADDRESS* get_mac_address(uint32_t ip_address){
    if(arp_table.find(ip_address) != arp_table.end()){
        return &arp_table[ip_address];
    }
    return &arp_table[inet_addr("0.0.0.0")]; // 브로드캐스트 주소 반환
}

void eth_send_handler(int sock_raw, char* buffer, uint32_t next_hop_ip, size_t packet_len, char* interface_name){
    struct ETH_HEADER *eth = reinterpret_cast<struct ETH_HEADER*>(buffer);

    // 이더넷 헤더 수정
    struct MAC_ADDRESS* src_mac = &mac_lan; // 기본값
    if(strcmp(interface_name, "wlan0") == 0) {
        src_mac = &mac_wan;
    }

    // 선택된 MAC 주소 대입
    for(int i = 0; i < 6; i++){
        eth->source_mac[i] = src_mac->mac[i];
    }

    // ARP 테이블에서 목적지 MAC 주소 조회 (여기서는 임시로 브로드캐스트 주소 사용)
    struct MAC_ADDRESS* dest_mac = get_mac_address(next_hop_ip);

    for(int i = 0; i < 6; i++){
        eth->destination_mac[i] = dest_mac->mac[i];
    }

    // 소켓 주소 설정
    struct sockaddr_ll socket_address;
    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_HEADER_CONSTANTS::ETH_P_IP);

    // 
    // socket_address.sll_ifindex = if_nametoindex("enxb0386cf1284b");
    socket_address.sll_ifindex = if_nametoindex(interface_name);
    socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, dest_mac->mac, 6);

    // 패킷 전송
    ssize_t sent_size = sendto(sock_raw, buffer, packet_len, 0,
                               (struct sockaddr*)&socket_address, sizeof(socket_address));

    if(sent_size < 0){
        print_errno_message("Error in sendto : ");
    } else {
        //source IP and destination IP for debug message
        struct IPV4_HEADER *ipv4_packet = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));
        
        if(debug_mode_packet_send){
            uint32_t src_ip = htonl(ipv4_packet->source_ip);
            uint32_t dst_ip = htonl(ipv4_packet->destination_ip);

            print_packet_info("[packet_send] ", buffer);
        }
    }
}