#ifndef DHCP_H
#define DHCP_H

#include <cstdint>

void init_dhcp_table();
uint16_t allocate_ip_num();
void refresh_dhcp_entries();

int dhcp_discover_handler(char* buffer);
int dhcp_request_handler(char* buffer);
int dhcp_read_handler(char *buffer);

#endif