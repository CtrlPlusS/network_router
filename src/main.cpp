// #include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <string>
#include <cstring>
#include <cerrno>
// #include <system_error>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "./router_info.h"
#include "./packets.h"
#include "./packet_read.h"
#include "./packet_send.h"
#include "./common.h"
#include "./route.h"
#include "./nat.h"
#include "./firewall.h"
#include "./dhcp.h"

void init_router(){
    auto& info = router_info::instance();

    // 라우터 정보 초기화
    info.init_router_info();

    // 라우팅 테이블 초기화
    init_routing_table();

    // MAC 주소 초기화
    init_mac_address();

    // NAT 테이블 초기화
    init_nat_table();

    // 방화벽 테이블 초기화
    init_firewall_table();

    init_dhcp_table();
}

int main(){
    auto& info = router_info::instance();

    init_router();

    // 2계층 소켓 생성
    int sock_raw = -1;
    {
        struct SOCKET_CONFIG temp_socket;
        temp_socket.domain = AF_PACKET;
        temp_socket.type = SOCK_RAW;
        temp_socket.protocol = htons(0x0003); // ETH_P_ALL

        sock_raw = socket(temp_socket.domain, temp_socket.type, temp_socket.protocol);
    }

    if(sock_raw < 0){
        print_errno_message("Error in socket : ");
        exit(-1);
    }

    // 패킷 수신
    char buffer[65536];
    struct ETH_HEADER *eth = nullptr;
    struct sockaddr_ll saddr;
    socklen_t saddr_len;
    time_t last_cleanup_time = time(NULL); // 마지막 청소 시간
    
    while(true){
        time_t current_time = time(NULL);
        if (current_time - last_cleanup_time >= 1) {
            cleanup_expired_nat_entries();
            refresh_dhcp_entries();
            last_cleanup_time = current_time;
            // if(debug_mode_main){
            //     printf("[main] nat clean done\n");
            // }
        }

        saddr_len = sizeof(saddr);
        // 버퍼 크기만큼 패킷 수신
        ssize_t sock_data = recvfrom(sock_raw, buffer, sizeof(buffer), 0, (struct sockaddr*)&saddr, &saddr_len);
        
        if(sock_data < 0){
            print_errno_message("Error in recvfrom : ");
            continue;
        }
        
        // 내부에서 보낸 패킷은 무시
        if(saddr.sll_pkttype == PACKET_OUTGOING || saddr.sll_pkttype == PACKET_LOOPBACK){
            //송신 패킷인 경우
            continue;
        }

        eth = reinterpret_cast<struct ETH_HEADER*>(buffer);

        if(memcmp(eth->source_mac, info.my_mac_lan.mac, 6) == 0 
            || memcmp(eth->source_mac, info.my_mac_wan.mac, 6) == 0){
            //내부에서 보낸 패킷인 경우
            continue;
        }

        uint16_t ptype = ntohs(eth->ethertype);

        // if(debug_mode_main){
        //     if(memcmp(eth->destination_mac, my_mac_lan.mac, 6) == 0 
        //     || memcmp(eth->destination_mac, my_mac_wan.mac, 6) == 0){
        //         printf("[main] Packet received on interface index %d, Ethertype: 0x%04X\n", saddr.sll_ifindex, ptype);
        //     }
        // }

        switch(ptype){
            case ETH_HEADER_CONSTANTS::ETH_P_IPV4:{
                uint32_t gateway = ipv4_read_handler(buffer, sock_raw, saddr.sll_ifindex);
                if(gateway == 0){
                    // 목적지가 로컬인 경우 처리 생략
                    break;
                }       

                struct IPV4_HEADER* ipv4 = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));
                struct ROUTE_ENTRY route = routing_table_find(ipv4->destination_ip);
                
                // 라우팅 테이블에 적힌 올바른 인터페이스로 전송
                eth_send_handler(sock_raw, buffer, gateway, sock_data, route.interface);
                break;
            }
            case ETH_HEADER_CONSTANTS::ETH_P_ARP:{
                uint32_t gateway = arp_read_handler(buffer, sock_raw, saddr.sll_ifindex);
                if(gateway == 0){
                    // 목적지가 로컬인 경우 처리 생략
                    break;
                }
                
                struct ARP_HEADER *arp = (struct ARP_HEADER*)(buffer + sizeof(struct ARP_HEADER));
                struct ROUTE_ENTRY route = routing_table_find((uint32_t)*arp->tpa);

                eth_send_handler(sock_raw, buffer, gateway, sock_data, route.interface);
                break;
            }
            case ETH_HEADER_CONSTANTS::ETH_P_IPV6:{
                // ipv6_handler(buffer);
                break;
            }
            default:{
                break;
            }
        }
    }

    close(sock_raw);
}