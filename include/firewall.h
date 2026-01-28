#ifndef FIREWALL_H
#define FIREWALL_H

#include <vector>
#include <iostream>
#include <cstdint>

#include "./router_info.h"
#include "./packets.h"

void init_firewall_table();
bool check_entry (FIREWALL_TABLE_ENTRY* condition, FIREWALL_TABLE_ENTRY* entry);
void create_firewall_entry(FIREWALL_TABLE_ENTRY entry);
uint8_t find_firewall_entry(FIREWALL_TABLE_ENTRY* entry);
uint8_t firewall_icmp_packet_find(IPV4_HEADER* ipv4_packet);
uint8_t firewall_tcp_packet_find(IPV4_HEADER* ipv4_packet);
uint8_t firewall_udp_packet_find(IPV4_HEADER* ipv4_packet);

#endif