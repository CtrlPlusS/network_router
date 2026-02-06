#ifndef DHCP_H
#define DHCP_H

#include <cstdint>
#include <string>

void init_dhcp_table();
uint16_t allocate_ip_num(std::string mac);
void refresh_dhcp_entries();

int dhcp_discover_handler(char* buffer);
int dhcp_request_handler(char* buffer);
int dhcp_read_handler(char *buffer);

#endif