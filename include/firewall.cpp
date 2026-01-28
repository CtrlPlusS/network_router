
#include <arpa/inet.h>

#include "./firewall.h"
#include "packets.h"

void init_firewall_table(){
    router_info::instance().firewall_table.clear();

    // create_firewall_entry({
    //     .source_ip = inet_addr("10.0.0.2"),
    //     .destination_ip = 0,
    //     .protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL,
    //     .source_port = 0,
    //     .destination_port = htons(443),
    //     .action = FIREWALL_ACTION_CONSTANTS::REJECT
    // });

    // create_firewall_entry({
    //     .source_ip = inet_addr("10.0.0.2"),
    //     .destination_ip = 0,
    //     .protocol = IPV4_HEADER_PROTOCOL_CONSTANTS::TCP_PROTOCOL,
    //     .source_port = 0,
    //     .destination_port = htons(80),
    //     .action = FIREWALL_ACTION_CONSTANTS::REJECT
    // });

    create_firewall_entry({
        .source_ip = 0,
        .destination_ip = 0,
        .protocol = 0,
        .source_port = 0,
        .destination_port = 0,
        .action = FIREWALL_ACTION_CONSTANTS::ACCEPT
    });
}

bool check_entry (FIREWALL_TABLE_ENTRY* condition, FIREWALL_TABLE_ENTRY* entry){
    if(condition->source_ip != 0 && condition->source_ip != entry->source_ip)
        return false;
    if(condition->destination_ip != 0 && condition->destination_ip != entry->destination_ip)
        return false;
    if(condition->source_port != 0 && condition->source_port != entry->source_port)
        return false;
    if(condition->destination_port != 0 && condition->destination_port != entry->destination_port)
        return false;
    if(condition->protocol != 0 && condition->protocol != entry->protocol)
        return false;

    return true;
}

void create_firewall_entry(FIREWALL_TABLE_ENTRY entry){
    router_info::instance().firewall_table.push_back(entry);
}

// 첫번째로 조건에 일치하는 값 찾음
uint8_t find_firewall_entry(FIREWALL_TABLE_ENTRY entry){
    auto& info = router_info::instance();
    auto it = info.firewall_table.begin();

    while(it != info.firewall_table.end()){
        if(check_entry(&(*it), &entry)){
            return (*it).action;
        }
        ++it;
    }

    return 0;
}

uint8_t firewall_icmp_packet_find(IPV4_HEADER* ipv4_packet){
    ICMP_HEADER* icmp_packet = reinterpret_cast<ICMP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);

    return find_firewall_entry({
        .source_ip = ipv4_packet->source_ip,
        .destination_ip = ipv4_packet->destination_ip,
        .protocol = ipv4_packet->protocol,
        .source_port = icmp_packet->identifier,
        .destination_port = icmp_packet->identifier
    });
}

uint8_t firewall_tcp_packet_find(IPV4_HEADER* ipv4_packet){
    TCP_HEADER* tcp_packet = reinterpret_cast<TCP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);

    return find_firewall_entry({
        .source_ip = ipv4_packet->source_ip,
        .destination_ip = ipv4_packet->destination_ip,
        .protocol = ipv4_packet->protocol,
        .source_port = tcp_packet->source_port,
        .destination_port = tcp_packet->destination_port
    });
}

uint8_t firewall_udp_packet_find(IPV4_HEADER* ipv4_packet){
    UDP_HEADER* udp_packet = reinterpret_cast<UDP_HEADER*>((uint8_t*)ipv4_packet + (ipv4_packet->version_ihl & 0x0F) * 4);

    return find_firewall_entry({
        .source_ip = ipv4_packet->source_ip,
        .destination_ip = ipv4_packet->destination_ip,
        .protocol = ipv4_packet->protocol,
        .source_port = udp_packet->source_port,
        .destination_port = udp_packet->destination_port
    });
}