// #include "./packets.h"
// #include "./common.cpp"
#include "./route.cpp"
#include "./packet_send.cpp"

extern bool debug_mode;

struct IPV4_HEADER* ipv4_read_handler(char* buffer){
    struct IPV4_HEADER *ipv4 = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    ipv4_send_handler(ipv4);

    if (debug_mode){
        uint32_t src_ip = htonl(ipv4->source_ip);
        uint32_t dst_ip = htonl(ipv4->destination_ip);
        uint32_t dest = htonl(route.destination);
        uint32_t gate = htonl(route.gateway);

        printf("[ipv4] Src : %d.%d.%d.%d -> Dst : %d.%d.%d.%d (Match %d.%d.%d.%d via %d.%d.%d.%d dev %s)\n",
            src_ip >> 24 & 0xFF,
            src_ip >> 16 & 0xFF,
            src_ip >> 8 & 0xFF,
            src_ip & 0xFF,
            dst_ip >> 24 & 0xFF,
            dst_ip >> 16 & 0xFF,
            dst_ip >> 8 & 0xFF,
            dst_ip & 0xFF,
            dest >> 24 & 0xFF,
            dest >> 16 & 0xFF,
            dest >> 8 & 0xFF,
            dest & 0xFF,
            gate >> 24 & 0xFF,
            gate >> 16 & 0xFF,
            gate >> 8 & 0xFF,
            gate & 0xFF,
            route.interface);
    } // 디버그용 출력

    return *ipv4;
}

struct ARP_HEADER arp_read_handler(char* buffer){
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    
    if(debug_mode){
        printf("[arp] : %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5],
        arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
    }

    return *arp;
}

// void ipv6_read_handler(char* buffer){
//     return;
// }