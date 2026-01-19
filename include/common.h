#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <cstdint>

int print_errno_message(const std::string& header);
void print_packet_info(char* msg, char* buffer);

uint32_t sum_1s_complement(uint16_t *buf, int len);
uint16_t finalize_checksum(uint32_t sum);
uint16_t calculate_checksum(uint16_t *addr, int len);
void udp_calculate_checksum(struct UDP_HEADER *udp, struct IPV4_HEADER *ip);
void tcp_calculate_checksum(struct TCP_HEADER *tcp, struct IPV4_HEADER *ip);
void icmp_calculate_checksum(struct ICMP_HEADER* icmp, struct IPV4_HEADER *ip);


// void print_ip(uint_32 ip);
// void print_mac()

#endif