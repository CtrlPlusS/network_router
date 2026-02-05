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

    // 디버그
    auto debug_options = data["debug"]; 
    freopen(std::string(debug_options["file_path"]).c_str(), "a", stdout);
    setbuf(stdout, NULL);
    debug_mode_core = debug_options["categories"]["core"];
    debug_mode_traffic = debug_options["categories"]["traffic"];
    debug_mode_nat = debug_options["categories"]["nat"];
    debug_mode_dhcp = debug_options["categories"]["dhcp"];
    debug_mode_security = debug_options["categories"]["security"];

    // nat
    auto nat_options = data["nat"];
    TCP_TIMEOUT = nat_options["tcp_timeout"];
    UDP_TIMEOUT = nat_options["udp_timeout"];
    ICMP_TIMEOUT = nat_options["icmp_timeout"];

    // dhcp
    auto dhcp_options = data["dhcp"];
    dhcp_ip_start_num = dhcp_options["range_start"];
    dhcp_ip_end_num = dhcp_options["range_end"];
    dhcp_offering_time = dhcp_options["lease_time"];
    dhcp_dns_server = inet_addr(std::string(dhcp_options["dns_server"]).c_str());

    // 방화벽
    auto firewall_options = data["firewall"];
    
    int default_policy = firewall_options["default_policy"].get<int>();
    // 방화벽 기본 설정
    create_firewall_entry({
        .source_ip = 0,
        .destination_ip = 0,
        .protocol = 0,
        .source_port = 0,
        .destination_port = 0,
        .action = static_cast<uint8_t>(default_policy)
    });
    // 차단리스트는 기본적으로 drop(로그 없음)
    for(auto block_entry : firewall_options["block_list"]){
        create_firewall_entry({
            .source_ip = inet_addr(block_entry.get<std::string>().c_str()),
            .destination_ip = 0,
            .protocol = 0,
            .source_port = 0,
            .destination_port = 0,
            .action = FIREWALL_ACTION_CONSTANTS::DROP
        });
    }
}

void router_info::load_debug_config(){
    std::ifstream file(config_file_pwd);
    json data = json::parse(file)["debug"];
    if(data["categories"]["core"] != debug_mode_core){
        debug_mode_core = data["categories"]["core"];
        PRINT_LOG_MESSAGE("core     : %5s -> %5s\n", 
            debug_mode_core ? "false" : "true",
            debug_mode_core ? "true" : "false");
    }

    if(data["categories"]["traffic"] != debug_mode_traffic){
        debug_mode_traffic = data["categories"]["traffic"];
        PRINT_LOG_MESSAGE("traffic     : %5s -> %5s\n", 
            debug_mode_traffic ? "false" : "true",
            debug_mode_traffic ? "true" : "false");
    }

    if(data["categories"]["nat"] != debug_mode_nat){
        debug_mode_nat = data["categories"]["nat"];
        PRINT_LOG_MESSAGE("nat     : %5s -> %5s\n", 
            debug_mode_nat ? "false" : "true",
            debug_mode_nat ? "true" : "false");
    }

    if(data["categories"]["dhcp"] != debug_mode_dhcp){
        debug_mode_dhcp = data["categories"]["dhcp"];
        PRINT_LOG_MESSAGE("dhcp     : %5s -> %5s\n", 
            debug_mode_dhcp ? "false" : "true",
            debug_mode_dhcp ? "true" : "false");
    }

    if(data["categories"]["security"] != debug_mode_security){
        debug_mode_security = data["categories"]["security"];
        PRINT_LOG_MESSAGE("security     : %5s -> %5s\n", 
            debug_mode_security ? "false" : "true",
            debug_mode_security ? "true" : "false");
    }
}

void router_info::load_wifi_config(){
    std::ifstream file(config_file_pwd);
    json data = json::parse(file)["wifi"];
    std::ofstream conf_file("/etc/hostapd/hostapd.conf");
    
    if (conf_file.is_open()) {
        conf_file << "interface=" << my_interface_lan << "\n";
        conf_file << "driver=nl80211\n";
        conf_file << "ssid=" << data["ssid"].get<std::string>() << "\n";
        conf_file << "hw_mode=g\n";
        conf_file << "channel=" << data["channel"].get<int>() << "\n";
        conf_file << "wmm_enabled=0\n";
        conf_file << "macaddr_acl=0\n";
        conf_file << "auth_algs=1\n";
        conf_file << "ignore_broadcast_ssid=0\n";
        conf_file << "wpa=2\n";
        conf_file << "wpa_passphrase=" << data["password"].get<std::string>() << "\n";
        conf_file << "wpa_key_mgmt=WPA-PSK\n";
        conf_file << "wpa_pairwise=TKIP\n";
        conf_file << "rsn_pairwise=CCMP\n";
        conf_file << "country_code=" << data["country_code"].get<std::string>() << "\n";
        
        conf_file.close();
    } else {
        return;
    }

    // 2. 기존 hostapd 종료 및 재시작 (system 명령어 사용)
    // -B: 백그라운드 실행
    system("sudo killall hostapd > /dev/null 2>&1"); // 기존 프로세스 죽이기
    system("sudo rfkill unblock wlan");
    system("sleep 3");
    system("sudo hostapd -B /etc/hostapd/hostapd.conf");
}