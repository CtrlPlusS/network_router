// #include "./packets.h"
// #include "./common.cpp"

void ipv4_handler(char* buffer){
    struct IPV4_HEADER *ipv4 = reinterpret_cast<struct IPV4_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    if(ipv4->protocol != 1) // ICMP 프로토콜만 처리
        return;

    uint32_t src_ip = ntohl(ipv4->source_ip);
    uint32_t dst_ip = ntohl(ipv4->destination_ip);

    // printf("%d.%d.%d.%d -> %d.%d.%d.%d [%d]\n",
    //     (src_ip >> 24) & 0xFF,
    //     (src_ip >> 16) & 0xFF,
    //     (src_ip >> 8) & 0xFF,
    //     src_ip & 0xFF,
    //     (dst_ip >> 24) & 0xFF,
    //     (dst_ip >> 16) & 0xFF,
    //     (dst_ip >> 8) & 0xFF,
    //     dst_ip & 0xFF,
    //     ipv4->protocol
    // );
}

void arp_handler(char* buffer){
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
    arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5],
    arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
}

// void ipv6_handler(char* buffer){
//     return;
// }