#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <cstdint>

int print_errno_message(const std::string& header);
void print_packet_info(char* buffer);
uint16_t calculate_checksum(uint16_t* data, size_t length);
// void print_ip(uint_32 ip);
// void print_mac()

#endif