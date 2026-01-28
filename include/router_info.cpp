#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "./router_info.h"
#include "./common.h"
#include "./packets.h"

std::string router_info::exec_command(const char* command){
    FILE *fp;
    char buff[128];
    std::string res;

    fp = popen(command, "r");
    if(fp == NULL){
        return "";
    }
    
    while(fgets(buff, 128, fp) != NULL){
        res += buff;
    }

    pclose(fp);

    size_t first = res.find_first_not_of(" \t\n\r");
    size_t last = res.find_last_not_of(" \t\n\r");
    return res.substr(first, (last - first + 1));
}

void router_info::get_wan_info(int sock){
    struct ifreq ifr;

    std::string command;
    command = "ip route show default | awk '/default/ {print $5}' | head -n 1";
    my_interface_wan = exec_command(command.data());
    command = "ip route show default | awk '/default/ {print $3}' | head -n 1";
    my_ipv4_wan_gateway = inet_addr(exec_command(command.data()).data());
    
    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, my_interface_wan.data(), IFNAMSIZ-1); // wan interface
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0){
        print_errno_message("[router_info] Error in getting WAN IP address : ");
    }
    else{
       my_ipv4_wan_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    }

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        print_errno_message("[router_info] Error in getting WAN MAC address : ");
    }
    else{
        memcpy(&my_mac_wan, &ifr.ifr_hwaddr.sa_data, 6);
    }
}

void router_info::get_lan_info(int sock){
    struct ifreq ifr;

    std::string command;
    command = "ls /sys/class/net | grep ^wl | head -n 1";
    my_interface_lan = exec_command(command.data());
    command = "ip -4 addr show " + my_interface_lan + " | grep inet | awk '{print $2}' | cut -d/ -f1";
    my_ipv4_lan_gateway = inet_addr(exec_command(command.data()).data());
    
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, my_interface_lan.data(), IFNAMSIZ-1); // lan interface
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0){
        print_errno_message("[router_info] Error in getting LAN IP address : ");
    }
    else{
        my_ipv4_lan_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    }

    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0){
        print_errno_message("[router_info] Error in getting LAN MAC address : ");
    }
    else{
        memcpy(&my_mac_lan, &ifr.ifr_hwaddr.sa_data, 6);
    }
}

void router_info::init_router_info(){
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

    get_wan_info(sock);
    get_lan_info(sock);

    close(sock);
}

void router_info::load_config(){
    // json 불러와서 디버그
}