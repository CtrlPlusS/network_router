#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "./router_info.h"
#include "./common.h"
#include "./packets.h"

extern bool debug_mode_router_info;

struct MAC_ADDRESS mac_lan = {0xb0, 0x38, 0x6c, 0xf1, 0x28, 0x4b};
struct MAC_ADDRESS mac_wan = {0x2c, 0xcf, 0x67, 0x2e, 0x1f, 0x85};

uint32_t my_ipv4_lan_ip; // = inet_addr("10.0.0.1");    라우터 ip
uint32_t my_ipv4_wan_ip; // = inet_addr("192.168.0.0"); 외부망 ip

void get_wan_ip(int sock){
    struct ifreq ifr;
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ-1); // wan interface
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0){
        print_errno_message("Error in getting WAN IP address : ");
        close(sock);
        exit(-1);
    }

    my_ipv4_wan_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}

void get_lan_ip(int sock){
    struct ifreq ifr;
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "enxb0386cf1284b", IFNAMSIZ-1); // lan interface
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0){
        print_errno_message("Error in getting LAN IP address : ");
        close(sock);
        exit(-1);
    }

    my_ipv4_lan_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}

void init_router_info(){
    // get_wan_ip, get_lan_ip 함수 사용해서 ip 초기화
    // socket열어서 ioctl로 ip 가져오기

    int sock = -1;
    {
        struct SOCKET_CONFIG temp_socket;
        temp_socket.domain = AF_INET;
        temp_socket.type = SOCK_DGRAM;
        temp_socket.protocol = 0;

        sock = socket(temp_socket.domain, temp_socket.type, temp_socket.protocol);
    }

    if(sock < 0){
        print_errno_message("Error in making socket for initializing router : ");
        exit(-1);
    }

    get_wan_ip(sock);
    get_lan_ip(sock);

    close(sock);

    if(debug_mode_router_info){
        struct in_addr lan_addr, wan_addr;
        lan_addr.s_addr = my_ipv4_lan_ip;
        wan_addr.s_addr = my_ipv4_wan_ip;

        printf("[router_info] MAC LAN: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac_lan.mac[0], mac_lan.mac[1], mac_lan.mac[2],
               mac_lan.mac[3], mac_lan.mac[4], mac_lan.mac[5]);
        printf("[router_info] MAC WAN: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac_wan.mac[0], mac_wan.mac[1], mac_wan.mac[2],
               mac_wan.mac[3], mac_wan.mac[4], mac_wan.mac[5]);
        printf("[router_info] LAN IP: %s\n", inet_ntoa(lan_addr));
        printf("[router_info] WAN IP: %s\n", inet_ntoa(wan_addr));
    }
}