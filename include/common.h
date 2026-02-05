#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <cstdint>
#include <sys/time.h>

#define PRINT_LOG_MESSAGE(fmt, ...) do { \
    struct timeval tv; \
    gettimeofday(&tv, NULL); \
    struct tm *t = localtime(&tv.tv_sec); \
    char time_buf[20]; \
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", t); \
    printf("[%s.%03ld] " fmt, time_buf, tv.tv_usec / 1000, ##__VA_ARGS__); \
} while(0)

#define DEBUG_HEADER(type, fmt, ...) \
    printf("\n=== [%s] " fmt " ===============\n", type, ##__VA_ARGS__)

int print_errno_message(const std::string& header);
void print_packet_info(std::string msg, char* buffer);

uint32_t sum_1s_complement(uint16_t *buf, int len);
uint16_t finalize_checksum(uint32_t sum);
uint16_t calculate_checksum(uint16_t *addr, int len);
void udp_calculate_checksum(struct UDP_HEADER *udp, struct IPV4_HEADER *ip);
void tcp_calculate_checksum(struct TCP_HEADER *tcp, struct IPV4_HEADER *ip);
void icmp_calculate_checksum(struct ICMP_HEADER* icmp, struct IPV4_HEADER *ip);


// void print_ip(uint_32 ip);
// void print_mac()

#endif