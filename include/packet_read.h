#ifndef PACKET_READ_H
#define PACKET_READ_H

#include "./packets.h"

void tcp_calculate_checksum(struct TCP_HEADER* tcp_packet, struct IPV4_HEADER* ipv4_packet);
void udp_calculate_checksum(struct UDP_HEADER* tcp_packet, struct IPV4_HEADER* ipv4_packet);

bool nat_inbound_handler(struct IPV4_HEADER* ipv4_packet);
void nat_outbound_handler(struct IPV4_HEADER* ipv4_packet);

void my_packet_icmp_handler(struct IPV4_HEADER* ipv4_packet);
void my_packet_handler(); // 재전송 필요시 true 반환

uint32_t ipv4_read_handler(char* buffer);
uint32_t arp_read_handler(char* buffer);

#endif