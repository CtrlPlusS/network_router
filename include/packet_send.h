#ifndef PACKET_SEND_H
#define PACKET_SEND_H

#include <map>
#include "./packets.h"

extern std::map<uint32_t, struct MAC_ADDRESS> arp_table;
extern struct MAC_ADDRESS my_mac;

void init_mac_address(uint8_t mac[6]);
struct MAC_ADDRESS* get_mac_address(uint32_t ip_address);
void eth_send_handler(int sock_raw, char* buffer, uint32_t next_hop_ip, size_t packet_len);

#endif