#ifndef packets_header
#define packets_header
struct ETH_HEADER { // Ethernet II 프레임 헤더
    uint8_t destination_mac[6];
    uint8_t source_mac[6];
    uint16_t ethertype;
} __attribute__((packed));

enum ETH_HEADER_CONSTANTS : uint16_t {
    ETH_P_IP = 0x0800,   // IPv4
    ETH_P_ARP = 0x0806,  // ARP
    ETH_P_IPV6 = 0x86DD  // IPv6
};

struct ARP_HEADER {
    uint16_t htype;    // Hardware Type
    uint16_t ptype;    // Protocol Type
    uint8_t hlen;      // Hardware Address Length
    uint8_t plen;      // Protocol Address Length
    uint16_t oper;     // Operation Code
    uint8_t sha[6];    // Sender Hardware Address
    uint8_t spa[4];    // Sender Protocol Address
    uint8_t tha[6];    // Target Hardware Address
    uint8_t tpa[4];    // Target Protocol Address
} __attribute__((packed));

struct SOCKET_CONFIG{
    int domain;
    int type;
    int protocol;
} __attribute__((packed));

struct IPV4_HEADER {
    uint8_t version_ihl;        // Version (4 bits) + Internet header length (4 bits)
    uint8_t type_of_service;    // Type of service
    uint16_t total_length;      // Total length
    uint16_t identification;    // Identification
    uint16_t flags_fragment_offset; // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t time_to_live;       // Time to live
    uint8_t protocol;           // Protocol
    uint16_t header_checksum;   // Header checksum
    uint32_t source_ip;         // Source address
    uint32_t destination_ip;    // Destination address
} __attribute__((packed));
#endif