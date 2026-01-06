#include <sys/socket.h>   // socket(), recvfrom()
#include <arpa/inet.h>    // htons(), ntohs()
#include <netinet/in.h>   // 프로토콜 정의
#include <linux/if_ether.h> // ETH_P_ALL, ETH_P_ARP, struct ethhdr
#include <net/ethernet.h>   // struct ether_header (대안)
#include <netinet/if_ether.h> // struct ether_arp
#include <iostream>
#include <string>
#include <unistd.h>       // close()
#include <cerrno>
#include <vector>
#include <system_error>

using namespace std;

struct SOCKET_CONFIG {
    int domain;
    int type;
    int protocol;
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
};

//jsdoc형식으로
/**
* @brief Print error message corresponding to errno
* @param header 메시지 앞에 출력할 헤더 문자열
* @return errno 값
* @note Uses std::error_code to get the error message
*/
int print_errno_message(const string& header){
    error_code ec(errno, generic_category());
    cout << header << ec.message() << endl;

    return ec.value();
}

void print_packet_info(char* buffer){
    struct ethhdr *eth = reinterpret_cast<struct ethhdr*>(buffer);
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ethhdr));

    cout << "=== Ethernet Header ===" << endl;
    cout << "Source MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02X", eth->h_source[i]);
        if(i < 5) printf(":");
    }
    cout << endl;

    cout << "Destination MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02X", eth->h_dest[i]);
        if(i < 5) printf(":");
    }
    cout << endl;

    cout << "=== ARP Header ===" << endl;
    cout << "Sender MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02X", arp->sha[i]);
        if(i < 5) printf(":");
    }
    cout << endl;

    cout << "Sender IP: ";
    for(int i = 0; i < 4; i++){
        printf("%d", arp->spa[i]);
        if(i < 3) printf(".");
    }
    cout << endl;

    cout << "Target MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02X", arp->tha[i]);
        if(i < 5) printf(":");
    }
    cout << endl;

    cout << "Target IP: ";
    for(int i = 0; i < 4; i++){
        printf("%d", arp->tpa[i]);
        if(i < 3) printf(".");
    }
    cout << endl;
}

int main() {
    // 2계층 소켓 생성
    int sock_raw = -1;
    {
        struct SOCKET_CONFIG temp_socket;
        temp_socket.domain = AF_PACKET;
        temp_socket.type = SOCK_RAW;
        temp_socket.protocol = htons(ETH_P_ALL);

        sock_raw = socket(temp_socket.domain, temp_socket.type, temp_socket.protocol);
    }

    if(errno < 0){
        print_errno_message("Error in socket : ");
        exit(-1);
    }

    // 패킷 수신
    char buffer[65536];
    struct ethhdr *eth = nullptr;

    while(true){
        // 버퍼 크기만큼 패킷 수신
        ssize_t sock_data = recvfrom(sock_raw, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if(sock_data < 0){
            print_errno_message("Error in recvfrom : ");
            continue;
        }
        eth = reinterpret_cast<struct ethhdr*>(buffer);

        unsigned short ptype = ntohs(eth->h_proto);
        // ARP 패킷만 처리
        if(ptype != ETH_P_ARP) continue;
        
        struct ether_arp *arp = reinterpret_cast<struct ether_arp*>(buffer + sizeof(struct ethhdr));
        printf("%d.%d.%d.%d\n", arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
    }


    close(sock_raw);
}