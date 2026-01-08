#ifndef PACKET_READ_H
#define PACKET_READ_H

#include "./packets.h"

uint32_t ipv4_read_handler(char* buffer);
struct ARP_HEADER arp_read_handler(char* buffer);

#endif