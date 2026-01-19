#ifndef FIREWALL_H
#define FIREWALL_H

#include <vector>
#include <iostream>
#include <cstdint>

#include "./packets.h"

enum FIREWALL_ACTION_CONSTANTS : uint8_t {
    ACCEPT = 0,
    DROP = 1,
    REJECT = 2, // 차단 메시지 전송
};

struct FIREWALL_TABLE_ENTRY {
    uint32_t source_ip;
    uint32_t destination_ip;
    uint8_t protocol;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t action;
};

extern std::vector<FIREWALL_TABLE_ENTRY> firewall_table;

void init_firewall_table();
bool check_entry (FIREWALL_TABLE_ENTRY* condition, FIREWALL_TABLE_ENTRY* entry);
void create_firewall_entry(FIREWALL_TABLE_ENTRY entry);
uint8_t find_firewall_entry(FIREWALL_TABLE_ENTRY* entry);
uint8_t firewall_icmp_packet_find(IPV4_HEADER* ipv4_packet);
uint8_t firewall_tcp_packet_find(IPV4_HEADER* ipv4_packet);
uint8_t firewall_udp_packet_find(IPV4_HEADER* ipv4_packet);

#endif