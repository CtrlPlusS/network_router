#ifndef route_header
#define route_header

#include <vector>

struct ROUTE_ENTRY {
    uint32_t destination; // 목적지 네트워크 주소
    uint32_t netmask;     // 서브넷 마스크
    uint32_t gateway;    // 게이트웨이 주소
    char interface[16];  // 출구 인터페이스 이름
    int metric;        // 메트릭 값
};

extern std::vector<ROUTE_ENTRY> routing_table;

void routing_table_init();
struct ROUTE_ENTRY routing_table_find(uint32_t src);

#endif