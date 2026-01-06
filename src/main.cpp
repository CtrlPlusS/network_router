#include <iostream>
#include <unistd.h>
#include <stdint.h>
#include <string>
#include <cerrno>
#include <system_error>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "./packets.h"
#include "./packet_read.cpp"
#include "./common.cpp"
#include "./route.h"

using namespace std;

int main() {
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

    while(true){
        // 버퍼 크기만큼 패킷 수신
        ssize_t sock_data = recvfrom(sock_raw, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if(sock_data < 0){
            print_errno_message("Error in recvfrom : ");
            continue;
        }
        eth = reinterpret_cast<struct ETH_HEADER*>(buffer);

        uint16_t ptype = ntohs(eth->ethertype);
        
        switch(ptype){
            case ETH_HEADER_CONSTANTS::ETH_P_IP:
                ipv4_handler(buffer);
                break;
            case ETH_HEADER_CONSTANTS::ETH_P_ARP:
                arp_handler(buffer);
                break;
            case ETH_HEADER_CONSTANTS::ETH_P_IPV6:
                // ipv6_handler(buffer);
                continue;
            default:
                continue;
        }
    }

    close(sock_raw);
}