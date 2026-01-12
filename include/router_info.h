#ifndef ROUTER_INFO_H
#define ROUTER_INFO_H

#include <cstdint>
#include <arpa/inet.h>

#include "./packets.h"

extern struct MAC_ADDRESS mac_lan;
extern struct MAC_ADDRESS mac_wan;

extern uint32_t my_ipv4_lan_ip;    // 라우터 ip
extern uint32_t my_ipv4_wan_ip; // 외부망 ip

void get_wan_ip(int sock);
void get_lan_ip(int sock);
void init_router_info();

#endif