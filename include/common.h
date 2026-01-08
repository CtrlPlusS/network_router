#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <cstdint>

int print_errno_message(const std::string& header);
void print_packet_info(char* buffer);

#endif