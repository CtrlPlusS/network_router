// #include <iostream>
#include <cstring>
#include <map>
#include <queue>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
// #include <sys/socket.h>
// #include <netinet/in.h>

#include "./router_info.h"
#include "./packet_send.h"
#include "./common.h"
#include "./packets.h"
#include "./nat.h"

void init_mac_address(){
    router_info::instance().arp_table.clear();

    // arp_table[inet_addr("172.16.102.1")] = {0x2c, 0xfa, 0xa2, 0xfd, 0x55, 0xb8}; // wlan0 MAC 주소
    // arp_table[inet_addr("0.0.0.0")] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; // 브로드캐스트 주소
    // arp_table[inet_addr("10.0.0.2")] = {0x00, 0x2b, 0x67, 0xfe, 0x96, 0x4e}; // 노트북 MAC 주소 
}

void arp_broadcast_send_handler(int sock, uint32_t next_hop, int if_index, struct MAC_ADDRESS* src_mac, uint32_t src_ip){
    char buffer[sizeof(ETH_HEADER) + sizeof(ARP_HEADER)];
    struct ETH_HEADER* eth_packet = reinterpret_cast<struct ETH_HEADER*>(buffer);
    struct ARP_HEADER* arp_packet = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    memset(eth_packet->destination_mac, 0xFF, 6);
    eth_packet->ethertype = htons(ETH_HEADER_CONSTANTS::ETH_P_ARP);

    arp_packet->htype = htons(1);
    arp_packet->ptype = htons(0x0800);
    arp_packet->hlen = 6;
    arp_packet->plen = 4;
    arp_packet->oper = htons(1);

    memcpy(arp_packet->sha, src_mac->mac, 6);
    memcpy(arp_packet->spa, &src_ip, 4);
    memset(arp_packet->tha, 0x00, 6);
    memcpy(arp_packet->tpa, &next_hop, 4);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_HEADER_CONSTANTS::ETH_P_ARP);
    sll.sll_ifindex = if_index;
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xFF, 6);

    
    size_t size = sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));
}   

void pending_packet_send_handler(std::queue<std::vector<char>>& queue, int sock, uint32_t next_hop, int if_index){
    while(!queue.empty()){
        std::vector<char> packet_vector = queue.front();
        queue.pop();

        char* packet = packet_vector.data();

        // debug 모드에 나중에 추가
        // if(packet_vector.size() > 1514){
        //     printf("[packet_send] packet size too big(%d)\n", packet_vector.size());
        // }

        struct ETH_HEADER* eth_packet = reinterpret_cast<ETH_HEADER*>(packet);
        struct MAC_ADDRESS* dest_mac = get_mac_address(next_hop);
        if(dest_mac == NULL)
            continue;
        
        memcpy(eth_packet->destination_mac, dest_mac, 6);

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_HEADER_CONSTANTS::ETH_P_IPV4);
        sll.sll_ifindex = if_index;
        sll.sll_halen = 6;
        memcpy(sll.sll_addr, dest_mac->mac, 6);

        size_t size = sendto(sock, packet, packet_vector.size(), 0, (struct sockaddr*)&sll, sizeof(sll));
        
        // debug 모드에 나중에 추가
        // if(size < 0){
        //     printf("[packet_send] error sending packets in pending_packet_send_handler\n");
        // }
    }
}

/**
 * @brief IP 주소에 해당하는 MAC 주소를 반환합니다.
 * @param ip_address IP 주소
 * @return MAC 주소
 */
struct MAC_ADDRESS* get_mac_address(uint32_t ip_address){
    auto& info = router_info::instance();
    if(info.arp_table.find(ip_address) != info.arp_table.end()){
        return &info.arp_table[ip_address];
    }

    return NULL; // 브로드캐스트 주소 반환
}

void eth_send_handler(int sock_raw, char* buffer, uint32_t next_hop_ip, size_t packet_len, char* interface_name){
    auto& info = router_info::instance();
    struct ETH_HEADER *eth = reinterpret_cast<struct ETH_HEADER*>(buffer);
    struct sockaddr_ll socket_address;

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_halen = ETH_ALEN;
    int if_index = if_nametoindex(interface_name);
    socket_address.sll_ifindex = if_index;

    // 이더넷 헤더 수정
    struct MAC_ADDRESS* src_mac = &info.my_mac_lan; // 기본값
    uint32_t src_ip = info.my_ipv4_lan_ip;
    if(strcmp(interface_name, info.my_interface_wan.data()) == 0) {
        src_mac = &info.my_mac_wan;
        src_ip = info.my_ipv4_wan_ip;
    }
    memcpy(eth->source_mac, src_mac->mac, 6);

    struct MAC_ADDRESS* dest_mac = get_mac_address(next_hop_ip);
    if(dest_mac == NULL){
        // 일단 송신 중단하고 큐에 담기
        std::vector<char> packet_copy(buffer, buffer + packet_len);
        info.pending_packets[next_hop_ip].push(packet_copy);

        // 브로드캐스트 수행
        arp_broadcast_send_handler(sock_raw, next_hop_ip, if_index, src_mac, src_ip);

        return;
    }

    memcpy(eth->destination_mac, dest_mac->mac, 6);
    socket_address.sll_protocol = eth->ethertype;
    memcpy(socket_address.sll_addr, dest_mac->mac, 6);

    // 패킷 전송
    ssize_t sent_size = sendto(sock_raw, buffer, packet_len, 0,
                               (struct sockaddr*)&socket_address, sizeof(socket_address));

    if(sent_size < 0){
        print_errno_message("[packet_send] Error in sendto : ");
    } else {
        if(info.debug_mode_traffic){
            print_debug_header("traffic", "packet send");
            print_packet_info("[traffic]", buffer);
        }
    }
}

void dhcp_send_handler(int sock, char* buffer, int packet_len, int if_index){
    // 소켓 주소 설정
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_HEADER_CONSTANTS::ETH_P_IPV4);
    sll.sll_ifindex = if_index;
    sll.sll_halen = 6;
    
    // sockaddr의 목적지도 브로드캐스트로 설정
    memset(sll.sll_addr, 0xFF, 6);

    // 4. 전송
    ssize_t sent_size = sendto(sock, buffer, packet_len, 0,
                               (struct sockaddr*)&sll, sizeof(sll));

    if (sent_size < 0) {
        print_errno_message("Error in send_dhcp_response: ");
    } else {
        // 나중에 debug 추가
        // if(debug_mode_packet_send){
        //     printf("[packet_send] Response Sent (%ld bytes) via Interface Index %d\n", sent_size, if_index);
        // }
    }
}