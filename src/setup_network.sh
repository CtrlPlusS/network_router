#!/bin/bash

LAN_IF="eth1"
WAN_IF="wlan0"

# 1. 인터페이스 활성화
ip link set $LAN_IF up
ip link set $WAN_IF up

# 2. LAN IP 할당
ip addr flush dev $LAN_IF
ip addr add 10.0.0.1/24 dev $LAN_IF

# 3. 커널 포워딩 비활성화 (사용자 프로그램이 직접 처리하므로 끔)
sysctl -w net.ipv4.ip_forward=0

# 4. 기존 iptables 규칙 초기화 (커널 NAT 방해 방지)
iptables -F
iptables -t nat -F
iptables -P FORWARD DROP # 커널은 포워딩하지 말고 버려라 (프로그램이 직접 함)

# 5. ARP 수동 등록 (노트북 -> 라즈베리 파이 패킷 수신용)
# ip neigh replace 10.0.0.2 lladdr 00:2b:67:fe:96:4e dev $LAN_IF

sudo iptables -F
sudo iptables -A OUTPUT -p tcp --sport 10000:65535 --tcp-flags RST RST -j DROP
echo "iptable setup complete"

echo "C++ NAT Testing Environment Ready!"
echo "Kernel IP Forwarding: OFF (User program will handle routing)"