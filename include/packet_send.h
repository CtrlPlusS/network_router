#ifndef PACKET_SEND_H
#define PACKET_SEND_H

#include <map>
#include "./packets.h"

extern std::map<uint32_t, struct MAC_ADDRESS> arp_table;

void init_mac_address();
struct MAC_ADDRESS* get_mac_address(uint32_t ip_address);
void eth_send_handler(int sock_raw, char* buffer, uint32_t next_hop_ip, size_t packet_len, char* interface_name);
void dhcp_send_handler(int sock, char* buffer, int packet_len, int if_index);

#endif