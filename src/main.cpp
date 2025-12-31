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

int print_errno_message(const string& header){
    error_code ec(errno, generic_category());
    cout << header << ec.message() << endl;

    return ec.value();
}

int main() {
    int sock_raw = -1;
    {
        struct SOCKET_CONFIG temp_socket;
        temp_socket.domain = AF_PACKET;
        temp_socket.type = SOCK_RAW;
        temp_socket.protocol = htons(ETH_P_ALL);

        int sock_raw = socket(temp_socket.domain, temp_socket.type, temp_socket.protocol);
    }

    if(sock_raw < 0){
        print_errno_message("Error in socket : ");
        exit(-1);
    }

    close(sock_raw);
}