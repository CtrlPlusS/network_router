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

using namespace std;

extern std::vector<ROUTE_ENTRY> routing_table;
extern struct MAC_ADDRESS mac_lan;
extern struct MAC_ADDRESS mac_wan;

bool debug_mode_main = false;
bool debug_mode_common = false;
bool debug_mode_packet_send = false;
bool debug_mode_packet_read = false;
bool debug_mode_route = false;
bool debug_mode_router_info = true;
bool debug_mode_nat = false;
bool debug_mode_firewall = true;

void init_router(){
    printf("===== [debug mode] =====\n");
    printf("debug_mode_main: %s\n", debug_mode_main ? "true" : "false");
    printf("debug_mode_common: %s\n", debug_mode_common ? "true" : "false");
    printf("debug_mode_packet_send: %s\n", debug_mode_packet_send ? "true" : "false");
    printf("debug_mode_packet_read: %s\n", debug_mode_packet_read ? "true" : "false");
    printf("debug_mode_route: %s\n", debug_mode_route ? "true" : "false");
    printf("debug_mode_router_info: %s\n", debug_mode_router_info ? "true" : "false");
    printf("debug_mode_nat: %s\n", debug_mode_nat ? "true" : "false");
    printf("debug_mode_firewall: %s\n", debug_mode_firewall ? "true" : "false");

    // 라우터 정보 초기화
    init_router_info();

    // 라우팅 테이블 초기화
    routing_table_init();

    // MAC 주소 초기화
    init_mac_address();

    // NAT 테이블 초기화
    init_nat_table();

    // 방화벽 테이블 초기화
    init_firewall_table();
}

int main(){
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
    char* interface_name;
    struct ETH_HEADER *eth = nullptr;
    struct sockaddr_ll saddr;
    socklen_t saddr_len;
    time_t last_cleanup_time = time(NULL); // 마지막 청소 시간
    
    if(debug_mode_main){
        printf("[main] loop start\n");
    }
    while(true){
        time_t current_time = time(NULL);
        if (current_time - last_cleanup_time >= 1) {
            cleanup_expired_nat_entries();
            last_cleanup_time = current_time;
            if(debug_mode_main){
                printf("[main] nat clean done\n");
            }
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

        if(memcmp(eth->source_mac, mac_lan.mac, 6) == 0 
            || memcmp(eth->source_mac, mac_wan.mac, 6) == 0){
            //내부에서 보낸 패킷인 경우
            continue;
        }

        uint16_t ptype = ntohs(eth->ethertype);

        if(debug_mode_main){
            printf("[main] Packet received on interface index %d, Ethertype: 0x%04X\n", saddr.sll_ifindex, ptype);
        }

        switch(ptype){
            case ETH_HEADER_CONSTANTS::ETH_P_IP:{
                uint32_t gateway = ipv4_read_handler(buffer);
                if(gateway == 0){
                    // 목적지가 로컬인 경우 처리 생략
                    break;
                }
                // eth_send_handler(sock_raw, buffer, gateway, sock_data, "enxb0386cf1284b");        

                struct IPV4_HEADER *ipv4 = (struct IPV4_HEADER*)(buffer + sizeof(struct ETH_HEADER));
                struct ROUTE_ENTRY route = routing_table_find(ipv4->destination_ip);
                
                // 라우팅 테이블에 적힌 올바른 인터페이스로 전송
                eth_send_handler(sock_raw, buffer, gateway, sock_data, route.interface);
                break;
            }
            case ETH_HEADER_CONSTANTS::ETH_P_ARP:{
                uint32_t gateway = arp_read_handler(buffer);
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