#include <iostream>
#include <cerrno>
#include <system_error>
#include <string>

#include "./common.h"
#include "./packets.h"

extern bool debug_mode_common;

using namespace std;

//jsdoc형식으로
/**
* @brief Print error message corresponding to errno
* @param header 메시지 앞에 출력할 헤더 문자열
* @return errno 값
* @note Uses std::error_code to get the error message
*/
int print_errno_message(const string& header){
    error_code ec(errno, generic_category());
    cerr << header << ec.message() << endl;

    return ec.value();
}

/**
* @brief Print Ethernet and ARP packet information from buffer
* @param buffer 패킷 데이터가 담긴 버퍼
 */
void print_packet_info(char* buffer){
    struct ETH_HEADER *eth = reinterpret_cast<struct ETH_HEADER*>(buffer);
    struct ARP_HEADER *arp = reinterpret_cast<struct ARP_HEADER*>(buffer + sizeof(struct ETH_HEADER));

    cout << "=== Ethernet Header ===" << endl;
    cout << "Source MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02X", eth->source_mac[i]);
        if(i < 5) printf(":");
    }
    cout << endl;

    cout << "Destination MAC: ";
    for(int i = 0; i < 6; i++){
        printf("%02X", eth->destination_mac[i]);
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


/**
* @brief Calculate checksum for given data
* @param data 데이터 포인터
* @param length 데이터 길이 (바이트 단위)
* @return 계산된 체크섬 값
 */
 uint16_t calculate_checksum(uint16_t* data, size_t length){
    uint16_t *ptr = data;
    uint32_t sum = 0;
    
    while(length > 1){
        sum += *ptr++;
        length -= 2;
    }
    if(length == 1){
        sum += *(uint8_t*)ptr;
    }

    while(sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}