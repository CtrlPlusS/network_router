#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fstream>

#include "./router_info.h"
#include "./common.h"
#include "./packets.h"
#include "./firewall.h"

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

    if(debug_mode_core){
        DEBUG_HEADER("core", "router_info");
        PRINT_LOG_MESSAGE("[core] [lan] mac : %x:%x:%x:%x:%x:%x\n", 
            my_mac_lan.mac[0], my_mac_lan.mac[1], my_mac_lan.mac[2], my_mac_lan.mac[3], my_mac_lan.mac[4], my_mac_lan.mac[5]);
        PRINT_LOG_MESSAGE("[core] [lan] ip : %d.%d.%d.%d\n",
            (htonl(my_ipv4_lan_ip) >> 24) & 0xFF,
            (htonl(my_ipv4_lan_ip) >> 16) & 0xFF,
            (htonl(my_ipv4_lan_ip) >>  8) & 0xFF,
            (htonl(my_ipv4_lan_ip)      ) & 0xFF);
        PRINT_LOG_MESSAGE("[core] [lan] gatway : %d.%d.%d.%d\n", 
            (htonl(my_ipv4_lan_gateway) >> 24) & 0xFF,
            (htonl(my_ipv4_lan_gateway) >> 16) & 0xFF,
            (htonl(my_ipv4_lan_gateway) >>  8) & 0xFF,
            (htonl(my_ipv4_lan_gateway)      ) & 0xFF);
        PRINT_LOG_MESSAGE("[core] [lan] interface : %s\n", my_interface_lan.data());

        PRINT_LOG_MESSAGE("[core] [wan] mac : %x:%x:%x:%x:%x:%x\n", 
            my_mac_lan.mac[0], my_mac_wan.mac[1], my_mac_wan.mac[2], my_mac_wan.mac[3], my_mac_wan.mac[4], my_mac_wan.mac[5]);
        PRINT_LOG_MESSAGE("[core] [wan] ip : %d.%d.%d.%d\n",
            (htonl(my_ipv4_wan_ip) >> 24) & 0xFF,
            (htonl(my_ipv4_wan_ip) >> 16) & 0xFF,
            (htonl(my_ipv4_wan_ip) >>  8) & 0xFF,
            (htonl(my_ipv4_wan_ip)      ) & 0xFF);
        PRINT_LOG_MESSAGE("[core] [wan] gatway : %d.%d.%d.%d\n", 
            (htonl(my_ipv4_wan_gateway) >> 24) & 0xFF,
            (htonl(my_ipv4_wan_gateway) >> 16) & 0xFF,
            (htonl(my_ipv4_wan_gateway) >>  8) & 0xFF,
            (htonl(my_ipv4_wan_gateway)      ) & 0xFF);
        PRINT_LOG_MESSAGE("[core] [wan] interface : %s\n", my_interface_wan.data());
    }
}

void router_info::load_config(){
    std::ifstream file(config_file_pwd);
    json data = json::parse(file);

    auto debug_options = data["debug"]; 
    freopen(std::string(debug_options["file_path"]).c_str(), "w", stdout);
    debug_mode_core = debug_options["categories"]["core"];
    debug_mode_traffic = debug_options["categories"]["traffic"];
    debug_mode_nat = debug_options["categories"]["nat"];
    debug_mode_dhcp = debug_options["categories"]["dhcp"];
    debug_mode_security = debug_options["categories"]["security"];

    auto nat_options = data["nat"];
    TCP_TIMEOUT = nat_options["tcp_timeout"];
    UDP_TIMEOUT = nat_options["udp_timeout"];
    ICMP_TIMEOUT = nat_options["icmp_timeout"];

    auto dhcp_options = data["dhcp"];
    dhcp_ip_start_num = dhcp_options["range_start"];
    dhcp_ip_end_num = dhcp_options["range_end"];
    dhcp_offering_time = dhcp_options["lease_time"];
    dhcp_dns_server = inet_addr(std::string(dhcp_options["dns_server"]).c_str());

    auto firewall_options = data["firewall"];
    for(auto block_entry : firewall_options["block_list"]){
        create_firewall_entry({
            .source_ip = inet_addr(std::string(block_entry).c_str()),
            .destination_ip = 0,
            .protocol = 0,
            .source_port = 0,
            .destination_port = 0,
            .action = FIREWALL_ACTION_CONSTANTS::DROP
        });
    }
}