#ifndef ROUTER_INFO_H
#define ROUTER_INFO_H

#include <cstdint>
#include <arpa/inet.h>
#include <string>

#include "./packets.h"

extern struct MAC_ADDRESS my_mac_lan;
extern struct MAC_ADDRESS my_mac_wan;

extern uint32_t my_ipv4_lan_ip; // 라우터 ip
extern uint32_t my_ipv4_lan_gateway;
extern uint32_t my_ipv4_wan_ip; // 외부망 ip
extern uint32_t my_ipv4_wan_gateway;

extern std::string my_interface_lan;
extern std::string my_interface_wan;

std::string exec_command(char* command);
void get_wan_info(int sock);
void get_lan_info(int sock);
void init_router_info();

#endif