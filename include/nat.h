#ifndef NAT_H
#define NAT_H

#include <cstdint>
#include <cstdlib>
#include <unordered_map>
#include <ctime>

struct NAT_TABLE_ENTRY {
    uint32_t ip;
    uint16_t internal_port;
    uint16_t external_port;
    uint8_t protocol; // 1: ICMP, 6: TCP, 17: UDP
    time_t last_updated;
};

extern std::unordered_map<uint64_t, NAT_TABLE_ENTRY> lan_to_wan_table;
extern std::unordered_map<uint32_t, NAT_TABLE_ENTRY> wan_to_lan_table;

void init_nat_table();

bool is_lan_ip( uint32_t ip_address);

uint16_t allocate_tcp_port();
uint16_t allocate_udp_port();
uint16_t allocate_icmp_port();

void free_tcp_port(uint16_t port);
void free_udp_port(uint16_t port);

void update_nat_table(uint64_t key, struct NAT_TABLE_ENTRY& entry);
void update_table_entry_time(struct NAT_TABLE_ENTRY* entry);

NAT_TABLE_ENTRY find_nat_entry_by_internal(uint64_t internal_port);
NAT_TABLE_ENTRY find_nat_entry_by_external(uint8_t protocol, uint16_t external_port);

void cleanup_expired_nat_entries();

#endif