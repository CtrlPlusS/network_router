# Custom NAT Router Engine

## 개요 (Overview)
이 프로젝트는 리눅스 커널의 라우팅 기능을 사용하지 않고, C++과 Raw Socket을 사용하여 사용자 공간에서 직접 구현한 **NAT 라우터**입니다.

라즈베리파이 환경에서 동작하며, 이더넷 프레임 파싱부터 IP 패킷 포워딩, TCP/UDP 체크섬 계산, NAT 테이블 관리까지 네트워크 스택의 핵심 기능을 직접 처리합니다.

## 개발 환경 (Environment)

* **Hardware**: Raspberry Pi
* **OS**: Raspberry Pi OS (Linux)
* **Language**: C
* **Compiler**: GCC
* **External Libraries**: None (Standard C Libraries only)

## 주요 기능 (Key Features)

* **Raw Socket 제어**: `PF_PACKET`, `SOCK_RAW`를 사용하여 L2 레벨에서 패킷 직접 수신 및 송신
* **Ethernet & ARP**:
    * 이더넷 헤더 파싱 및 목적지 MAC 주소 검증
    * ARP Request/Reply 처리 및 동적 게이트웨이 MAC 주소 학습
* **IP Layer**:
    * IP 헤더 파싱 및 유효성 검사
    * 패킷 포워딩 (LAN <-> WAN)
    * IP Checksum 재계산
* **NAT (Network Address Translation)**:
    * 동적 포트 매핑 (Masquerading)
    * LAN 내부 사설 IP와 WAN 공인 IP 간의 주소 변환
    * TCP/UDP Checksum 재계산
* **TCP Support**:
    * TCP 3-Way Handshake 세션 추적 및 지원
    * Sequence Number 및 ACK Number 관리

## 성능 벤치마크 (Performance Benchmark)

현재 성능 측정 결과입니다. 추후 최적화 될 예정입니다.

* **측정 도구**: iPerf3
* **대상 서버**: speedtest.uztelecom.uz (Port 5201)
* **환경**: Raspberry Pi (Linux)

| 구분 | 업로드 (Tx) | 다운로드 (Rx) | 비고 |
| :--- | :--- | :--- | :--- |
| **Native (Direct)** | 46.6 Mbps | 11.4 Mbps | 라우터 엔진 미사용 (기준값) |
| **Router Engine(초기형)** | 5.93 Mbps | 2.81 Mbps | 본 프로젝트 엔진 구동 |
| **Router Engine(release로 compile)** | 5.11 Mbps | 3.32 Mbps | 약 11% (Tx) / **29% (Rx)** |
| **성능 유지율** | 약 12.7% | 약 24.6% | - |

## 빌드 및 실행 (Build & Run)

### 사전 요구 사항 (Prerequisites)
* CMake (버전 3.0 이상 권장)
* GCC 컴파일러
* 관리자 권한 (Raw Socket 사용 시 필수)

### 빌드 (Build)
CMake를 사용하여 빌드 시스템을 구성하고 컴파일을 수행합니다.

```bash
# 1. 빌드 설정 (빌드 디렉토리 'build' 생성 및 구성)
cmake -B build -S .

# 2. 프로젝트 빌드
cmake --build build