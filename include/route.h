#ifndef route_header
#define route_header

#include <vector>
#include <cstdint>

#include "./router_info.h"

extern std::vector<ROUTE_ENTRY> routing_table;

void init_routing_table();
struct ROUTE_ENTRY routing_table_find(uint32_t src);

#endif