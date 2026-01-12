#ifndef PACKET_READ_H
#define PACKET_READ_H

#include "./packets.h"

void calculate_checksum(IPV4_HEADER* ipv4_packet);
bool my_packet_handler(); // 재전송 필요시 true 반환
uint32_t ipv4_read_handler(char* buffer);
struct ARP_HEADER arp_read_handler(char* buffer);

#endif