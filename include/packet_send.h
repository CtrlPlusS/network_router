#ifndef PACKET_SEND_H
#define PACKET_SEND_H

#include <map>
#include <queue>
#include "./packets.h"

void init_mac_address();
void arp_broadcast_send_handler(int sock, uint32_t next_hop, int if_index, struct MAC_ADDRESS* src_mac, uint32_t src_ip);
void pending_packet_send_handler(std::queue<std::vector<char>>& queue, int sock, uint32_t next_hop, int if_index);
struct MAC_ADDRESS* get_mac_address(uint32_t ip_address);
void eth_send_handler(int sock_raw, char* buffer, uint32_t next_hop_ip, size_t packet_len, char* interface_name);
void dhcp_send_handler(int sock, char* buffer, int packet_len, int if_index);

#endif