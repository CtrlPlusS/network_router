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

#include "./packets.h"
#include "./packet_read.cpp"
#include "./common.cpp"
#include "./route.h"

using namespace std;

extern std::vector<ROUTE_ENTRY> routing_table;
bool debug_mode = true;

int main(){

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
    routing_table_init();
    
    while(true){
        // 버퍼 크기만큼 패킷 수신
        ssize_t sock_data = recvfrom(sock_raw, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if(sock_data < 0){
            print_errno_message("Error in recvfrom : ");
            continue;
        }
        eth = reinterpret_cast<struct ETH_HEADER*>(buffer);

        uint16_t ptype = ntohs(eth->ethertype);
        
        const char* interface_name = "veth-router";
        if(!if_nametoindex(interface_name)){
            continue;
        }

        // struct sockaddr_ll sll;
        // memset(&sll, 0, sizeof(sll));
        // sll.sll_family = AF_PACKET;
        // sll.sll_ifindex = if_nametoindex(interface_name);
        // sll.sll_protocol = htons(0x0003);

        // if(bind(sock_raw, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0){
        //     print_errno_message("Error in bind : ");
        //     continue;
        // }

        switch(ptype){
            case ETH_HEADER_CONSTANTS::ETH_P_IP:{
                struct IPV4_HEADER* ipv4_packet = ipv4_read_handler(buffer);
                if(ipv4_packet->protocol != 1) // ICMP 프로토콜만 처리
                    break;
                ipv4_send_handler();
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