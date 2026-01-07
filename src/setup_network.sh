#!/bin/bash

# 1. 기존 인터페이스 정리
sudo ip link delete veth-router 2>/dev/null

# 2. veth 쌍 생성
sudo ip link add veth-router type veth peer name veth-pc

# ==========================================
# 3. MAC 주소 강제 고정 (이게 핵심입니다!)
# ==========================================
# veth-router의 MAC을 aa:bb:cc:dd:ee:01 로 고정
sudo ip link set dev veth-router address aa:bb:cc:dd:ee:01
# veth-pc의 MAC을 aa:bb:cc:dd:ee:02 로 고정
sudo ip link set dev veth-pc address aa:bb:cc:dd:ee:02

# 4. IP 할당 및 인터페이스 켜기
sudo ip addr add 10.0.0.1/24 dev veth-router
sudo ip link set veth-router up

sudo ip addr add 10.0.0.2/24 dev veth-pc
sudo ip link set veth-pc up

# ==========================================
# 5. ARP 테이블 수동 등록 (Static ARP)
# ==========================================
# "10.0.0.2는 무조건 저 MAC 주소야"라고 리눅스 커널에 알려줌
# 이제 ping을 안 쳐도 바로 통신 가능
sudo ip neigh add 10.0.0.2 lladdr aa:bb:cc:dd:ee:02 dev veth-router
sudo ip neigh add 10.0.0.1 lladdr aa:bb:cc:dd:ee:01 dev veth-pc

# 6. 라우팅 등 추가 설정 (필요시)
sudo ip route add 8.8.8.8/32 via 10.0.0.1 dev veth-pc

echo " Network Setup Complete!"
