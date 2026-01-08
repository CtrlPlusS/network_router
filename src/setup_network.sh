#!/bin/bash

# 1. 인터페이스 이름 설정 (확인하신 이름 적용)
LAN_IF="enxb0386cf1284b"
WAN_IF="wlan0"

# 2. 인터페이스 활성화
sudo ip link set $LAN_IF up

# 3. LAN IP 할당 (기존 IP 삭제 후 새로 할당하여 충돌 방지)
sudo ip addr flush dev $LAN_IF
sudo ip addr add 10.0.0.1/24 dev $LAN_IF

# 4. 커널 IP 포워딩 활성화 (인터넷 공유의 핵심)
sudo sysctl -w net.ipv4.ip_forward=1

# ==========================================
# 5. ARP 테이블 수동 등록 (노트북/PC용)
# ==========================================
# 노트북 IP: 10.0.0.2, 노트북 MAC: 00:2b:67:fe:96:4e (로그에서 확인됨)
sudo ip neigh replace 10.0.0.2 lladdr 00:2b:67:fe:96:4e dev $LAN_IF

# ==========================================
# 6. NAT(IP Masquerade) 설정
# ==========================================
# LAN에서 들어온 패킷이 와이파이를 통해 나갈 수 있도록 변환
sudo iptables -t nat -F
sudo iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE
sudo iptables -A FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT
sudo iptables -A FORWARD -i $WAN_IF -o $LAN_IF -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "Hardware Router Setup Complete!"
echo "LAN: $LAN_IF (10.0.0.1)"
echo "WAN: $WAN_IF (Internet)"