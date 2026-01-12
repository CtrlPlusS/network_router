#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <system_error>

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

using namespace std;

extern std::vector<ROUTE_ENTRY> routing_table;
extern struct MAC_ADDRESS mac_lan;
extern struct MAC_ADDRESS mac_wan;

bool debug_mode_main = false;

void init_router(){
    // 라우터 정보 초기화
    init_router_info();

    // 라우팅 테이블 초기화
    routing_table_init();

    // MAC 주소 초기화
    init_mac_address();
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
    const char* interface_name = "enxb0386cf1284b";
    struct ETH_HEADER *eth = nullptr;
    struct sockaddr_ll saddr;
    socklen_t saddr_len;
    
    while(true){
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

        uint16_t ptype = ntohs(eth->ethertype);

        switch(ptype){
            case ETH_HEADER_CONSTANTS::ETH_P_IP:{
                uint32_t gateway = ipv4_read_handler(buffer);
                if(gateway == 0){
                    // 목적지가 로컬인 경우 처리 생략
                    break;
                }
                eth_send_handler(sock_raw, buffer, gateway, sock_data);
                break;
            }
            case ETH_HEADER_CONSTANTS::ETH_P_ARP:{
                struct ARP_HEADER arp_packet = arp_read_handler(buffer);
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