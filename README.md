Network Traffic Analyzer
========================

1. 프로젝트 개요
----------------
Network Traffic Analyzer는 C11로 작성한 PCAP 기반 네트워크 트래픽 및 기초 보안 분석 프로젝트입니다.
Ethernet II / IPv4 프레임에서 TCP·UDP 헤더 정보를 추출하고, 패킷 통계,
SYN 기반 포트 스캔 의심 탐지, SYN 급증 탐지, TCP 3-way handshake 상태 추적을 수행합니다.

목적
- 네트워크 패킷의 구조와 프로토콜 처리 과정 이해
- C 언어의 메모리 관리, 연결 리스트, 모듈 분리, 테스트 활용
- 보안관제(SOC) 업무와 관련된 기본적인 트래픽 관찰 및 이상 징후 탐지 실습

주의: 이 프로젝트는 학습용 분석기입니다. 경고는 공격 확정 판정이 아니며,
경고가 없다는 사실도 네트워크의 안전을 보장하지 않습니다.

2. 주요 기능
-------------
[PCAP Reader]
- Classic PCAP 파일 읽기 (마이크로초/나노초 타임스탬프 지원)
- Ethernet 링크 유형 처리
- 파일 내 각 패킷의 길이와 타임스탬프 판독

[Packet Parser]
- Ethernet II / IPv4 / TCP / UDP 파싱
- 출발지·목적지 IP, 포트, IP 길이, TCP Flags 추출
- 비정상 헤더의 길이 검증, 미지원 프레임 분리 집계

[Queue]
- 단일 연결 리스트 기반 FIFO 큐
- 삽입, 삭제, 빈 큐 확인, 메모리 해제
- 현재 main.c는 패킷을 큐에 넣은 뒤 바로 꺼내 처리합니다.
  즉, 비동기/멀티스레드 파이프라인이나 실제 버퍼링 기능은 구현하지 않았습니다.

[Security Analyzer]
- 패킷 및 IPv4 바이트 집계, 프로토콜별 TCP/UDP 집계
- 출발지 IP별 트래픽 집계 및 상위 10개 출발지 출력
- 10초 구간 내 동일 출발지→목적지의 서로 다른 목적지 포트
  20개 이상으로 SYN 시도가 관찰되면 포트 스캔 의심 경고
- 10초 구간 내 동일 출발지→목적지의 SYN 패킷이
  100개 이상이면 SYN 급증/플러드 의심 경고
- 동일 유형의 반복 경고에 10초 쿨다운 적용

[TCP Connection Tracking]
- 출발지/목적지 IP와 포트(4-tuple) 기반 연결 추적
- SYN → SYN/ACK → ACK 순서 관찰
- 완료된 handshake, 미완료 handshake, 반복 SYN, RST 종료 집계
- 진행 중인 handshake에 대한 타임아웃 처리
- 시간 역순 TCP 패킷 건너뛰기 및 추적 한도 집계

3. 파일 구조
-------------
NetworkTrafficAnalyzer/
|-- Makefile
|-- main.c
|-- packet.h
|-- queue.h
|-- queue.c
|-- parser.h
|-- parser.c
|-- pcap_reader.h
|-- pcap_reader.c
|-- security.h
|-- security.c
|-- conntrack.h
|-- conntrack.c
`-- tests/
    |-- test_framework.h
    |-- test_queue.c
    |-- test_parser.c
    |-- test_security.c
    `-- test_conntrack.c

* demo.pcap은 사용자가 별도로 준비하는 샘플 파일이며 필수 소스 파일은 아닙니다.

4. 요구 사항
-------------
- C11을 지원하는 C 컴파일러 (예: gcc 또는 clang)
- make
- macOS 또는 POSIX 계열 개발 환경에서 사용 가능하도록 작성한 빌드 구성
- 분석하려는 Classic PCAP 파일 (Ethernet 링크 유형)

5. 빌드 및 실행
----------------
프로젝트 루트 디렉터리에서:

    make clean
    make

기본 분석:

    ./analyzer demo.pcap

각 패킷의 상세 정보를 출력:

    ./analyzer demo.pcap --verbose

결과 저장:

    ./analyzer demo.pcap > connection_result.txt
    ./analyzer demo.pcap --verbose > connection_verbose.txt

화면 출력과 파일 저장을 동시에 하려면:

    ./analyzer demo.pcap | tee connection_result.txt

* Wireshark에서 저장한 기본 pcapng 형식은 지원하지 않습니다.
  Classic PCAP(.pcap) 형식으로 저장 또는 내보내야 합니다.

6. 테스트
-----------
전체 테스트 빌드 및 실행:

    make test

모듈별 실행:

    ./test_queue
    ./test_parser
    ./test_security
    ./test_conntrack

확인된 테스트 결과:

    Queue                    : 45 PASS / 0 FAIL
    Packet Parser            : 22 PASS / 0 FAIL
    Security Analyzer        : 26 PASS / 0 FAIL
    TCP Connection Tracking  :  9 PASS / 0 FAIL
    ----------------------------------------------
    TOTAL                    :102 PASS / 0 FAIL

위 결과는 작성된 테스트 사례의 통과 여부이며,
모든 입력에 대한 안전성·정확성을 증명하지는 않습니다.

7. 실제 PCAP 분석 사례
------------------------
Wireshark에서 수집한 샘플 PCAP을 대상으로 확인한 출력입니다.

    Parsed TCP/UDP: 5093 (TCP 46, UDP 5047)
    IPv4 bytes: 4808611
    Port scan alerts: 0
    SYN spike alerts: 0
    Unsupported: 36
    Invalid: 0

    === TCP Connection Tracking ===
    SYN packets: 1
    SYN/ACK responses: 1
    Completed handshakes: 1
    Incomplete handshakes: 0
    Repeated SYN: 0
    RST-terminated tracked connections: 1
    Out-of-order TCP packets skipped: 0
    SYN not tracked (capacity/allocation): 0

해석:
- 총 5,093개의 TCP/UDP 패킷을 파싱했습니다.
- TCP 3-way handshake의 플래그 순서가 1건 관찰되었습니다.
- 추적 중인 연결의 RST 종료가 1건 집계되었습니다.
- 이번 샘플에서는 두 SYN 기반 탐지 조건에 해당하는 경고가 없었습니다.

* 캡처 중간에 시작·종료된 연결은 실제 연결 상태와 다르게 집계될 수 있습니다.
* IPv4 bytes는 Ethernet 프레임 전체 길이가 아니라 IPv4 Total Length의 합입니다.

8. 설계 및 기술적 한계
-----------------------
- 지원: Classic PCAP + Ethernet II + IPv4의 TCP/UDP 패킷
- 미지원: pcapng, IPv6, VLAN 태그, IP 단편 재조립, ARP 등 비TCP/UDP 트래픽
- TCP checksum, sequence number, acknowledgment number의 정합성 검증 미구현
- TCP 연결 추적은 4-tuple과 Flags 순서 기반의 단순 모델입니다.
  실제 TCP 상태 머신을 완전히 재현하지 않으며, FIN 정상 종료 상태 추적도 미구현입니다.
- TCP 연결 미완료는 '캡처 안에서 확인되지 않음'을 뜻하며, 실제 연결 실패를 확정하지 않습니다.
- SYN 기반 탐지는 트래픽 패턴 경고일 뿐 공격 여부를 확정하지 않습니다.
  정상 재전송, 캡처 범위, 응답 여부에 따른 오탐/미탐 가능성이 있습니다.
- 현재 연결 및 트래픽 통계 구조는 연결 리스트·선형 탐색을 사용하므로
  대용량 트래픽 분석에 최적화되어 있지 않습니다.

9. 향후 개선 과제
------------------
- FIN 기반 연결 종료 처리 및 TCP 상태 추적 정교화
- TCP Sequence/Acknowledgment Number 검증
- 연결 성립률 및 미완료 SYN 비율을 활용한 탐지 개선
- CSV/JSON 리포트 출력
- IPv6, VLAN, pcapng 지원 범위 확대
- 대용량 입력에 대한 성능·메모리 사용량 검증

10. 데이터 취급 주의
---------------------
PCAP 파일에는 내부 IP 주소, 접속 대상, 통신 시간 등 네트워크 정보가
포함될 수 있습니다. 공개 Git 저장소에 실제 캡처 파일이나 verbose 로그를
올리기 전에 민감 정보 포함 여부를 반드시 검토하세요.

권장 .gitignore 예시:

    *.pcap
    *.pcapng
    *_verbose.txt
    connection_result.txt
    analyzer
    *.o
    test_queue
    test_parser
    test_security
    test_conntrack

라이선스: 별도로 지정하지 않았습니다.
