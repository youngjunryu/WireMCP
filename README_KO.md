![Wire-MCP Banner](Wire-MCP.png)

# WireMCP 한국어 가이드

WireMCP는 대형 언어 모델(LLM)에 실시간 네트워크 트래픽 분석 기능을 제공하기 위해 설계된 MCP(Model Context Protocol) 서버입니다. Wireshark의 `tshark`를 기반으로 한 도구를 활용하여 라이브 네트워크 데이터를 캡처·처리하고, LLM이 위협 헌팅, 네트워크 진단, 이상 탐지 등의 작업을 수행할 수 있도록 구조화된 컨텍스트를 제공합니다.

---

## 기능 (Features)

WireMCP는 다음 7가지 도구를 MCP 클라이언트에 노출합니다.

| 도구 | 설명 |
|------|------|
| **`capture_packets`** | 라이브 트래픽을 캡처하여 패킷 데이터를 JSON으로 반환합니다. IP 주소, 포트, HTTP 메서드 등 패킷 수준의 세부 정보를 분석할 수 있습니다. |
| **`get_summary_stats`** | 프로토콜 계층 통계를 제공합니다. TCP vs UDP 비율 등 트래픽 구성 현황을 한눈에 파악할 수 있습니다. |
| **`get_conversations`** | TCP/UDP 대화(Conversation) 통계를 제공합니다. 엔드포인트 간의 통신 흐름을 추적할 수 있습니다. |
| **`check_threats`** | 캡처된 IP를 URLhaus 블랙리스트와 대조하여 악성 활동 여부를 판단합니다. |
| **`check_ip_threats`** | 특정 IP 주소를 URLhaus 위협 피드와 비교하여 평판 및 위협 정보를 조회합니다. |
| **`analyze_pcap`** | 저장된 PCAP 파일을 분석하여 패킷 데이터를 JSON으로 제공합니다. 캡처 후 상세 분석에 활용합니다. |
| **`extract_credentials`** | PCAP 파일에서 HTTP Basic Auth, FTP, Telnet, Kerberos 등 프로토콜의 잠재적 인증 정보를 추출합니다. 보안 감사 및 포렌식 분석에 활용합니다. |

---

## 설치 방법

### 사전 요구사항

- **OS**: macOS / Windows / Linux
- **Wireshark**: [공식 사이트](https://www.wireshark.org/download.html)에서 설치 (`tshark`가 PATH에 등록되어 있어야 합니다)
- **Node.js**: v16 이상
- **npm**: 패키지 설치용

### Windows 환경 추가 설정

Windows에서 `tshark`가 PATH에 없을 경우, 환경변수 `TSHARK_PATH`에 전체 경로를 지정할 수 있습니다.

```
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
```

자동 탐색 순서: `TSHARK_PATH` 환경변수 → PATH 탐색 → `C:\Program Files\Wireshark\tshark.exe` → `C:\Program Files (x86)\Wireshark\tshark.exe`

### 설치 순서

```bash
# 1. 저장소 클론
git clone https://github.com/youngjunryu/WireMCP.git
cd WireMCP

# 2. 의존성 설치
npm install

# 3. 서버 실행 (정상 작동 확인용)
node index.js
```

---

## MCP 클라이언트 연동

### Claude Desktop

`claude_desktop_config.json` 파일에 아래 내용을 추가합니다.

- **macOS 경로**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows 경로**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wiremcp": {
      "command": "node",
      "args": [
        "/절대경로/WireMCP/index.js"
      ]
    }
  }
}
```

Windows 예시:

```json
{
  "mcpServers": {
    "wiremcp": {
      "command": "node",
      "args": [
        "C:\\Users\\사용자명\\WireMCP\\index.js"
      ],
      "env": {
        "TSHARK_PATH": "C:\\Program Files\\Wireshark\\tshark.exe"
      }
    }
  }
}
```

### Cursor

Cursor → Settings → MCP에서 `mcp.json`을 편집합니다.

```json
{
  "mcpServers": {
    "wiremcp": {
      "command": "node",
      "args": [
        "/절대경로/WireMCP/index.js"
      ]
    }
  }
}
```

---

## 실제 사용 사례

### 사례 1: 실시간 패킷 분석으로 이상 트래픽 탐지

**상황**: 회사 내부망에서 갑작스럽게 외부로 나가는 트래픽이 급증했습니다. 어떤 IP와 통신하는지 확인하고 싶습니다.

**LLM에게 요청**:
```
en0 인터페이스에서 10초 동안 패킷을 캡처해서, 외부 IP 통신 현황과 이상한 점이 있으면 알려줘.
```

**`capture_packets` 도구 실행 결과 예시**:
```json
[
  {
    "_source": {
      "layers": {
        "frame.number": ["1"],
        "ip.src": ["192.168.1.105"],
        "ip.dst": ["45.33.32.156"],
        "tcp.dstport": ["4444"],
        "frame.time": ["2025-03-09 14:23:01.123"]
      }
    }
  }
]
```

**LLM 분석 결과**:
> 192.168.1.105가 외부 IP 45.33.32.156의 4444 포트로 반복 접속하고 있습니다. 포트 4444는 Metasploit 리버스 셸에서 자주 사용되는 포트로, 해당 호스트의 악성코드 감염 여부를 점검할 필요가 있습니다.

---

### 사례 2: 프로토콜 통계로 네트워크 병목 진단

**상황**: 네트워크가 느린데 원인을 모르겠습니다.

**LLM에게 요청**:
```
현재 네트워크 트래픽 프로토콜 비율을 분석해서 병목 원인을 찾아줘.
```

**`get_summary_stats` 도구 실행 결과 예시**:
```
Protocol Hierarchy Statistics

eth                                      frames:1500 bytes:1823400
  ip                                     frames:1480 bytes:1800000
    tcp                                  frames:1200 bytes:1500000
      http                               frames:950  bytes:1300000
        data-text-lines                  frames:800  bytes:1200000
    udp                                  frames:280  bytes:300000
      dns                                frames:280  bytes:300000
```

**LLM 분석 결과**:
> 전체 트래픽의 63%가 HTTP이고, 그 중 84%가 텍스트 데이터입니다. DNS 쿼리가 280건으로 다소 많으며, 특정 호스트가 반복적으로 DNS를 조회하는 패턴일 수 있습니다. HTTP 트래픽을 발생시키는 상위 호스트를 추가로 확인해 보겠습니다.

---

### 사례 3: PCAP 파일로 사후 포렌식 분석

**상황**: 보안 사고가 발생했습니다. 사고 시점에 캡처된 `incident.pcap` 파일을 분석해야 합니다.

**LLM에게 요청**:
```
/home/analyst/incident.pcap 파일을 분석해서, 어떤 IP들이 통신했고 어떤 프로토콜을 사용했는지 정리해줘.
```

**`analyze_pcap` 도구 실행 결과 예시**:
```
Analyzed PCAP: /home/analyst/incident.pcap

Unique IPs:
192.168.0.10
203.0.113.55
10.0.0.1

URLs:
http://203.0.113.55/payload.exe
http://203.0.113.55/config.dat

Protocols:
eth:ethertype:ip:tcp
eth:ethertype:ip:tcp:http
```

**LLM 분석 결과**:
> 내부 호스트 192.168.0.10이 외부 IP 203.0.113.55에서 `payload.exe`와 `config.dat`를 HTTP로 다운로드했습니다. 이는 드라이브-바이 다운로드 또는 C2 통신 패턴과 일치합니다. 해당 IP를 위협 피드와 대조해 보겠습니다.

---

### 사례 4: PCAP에서 평문 인증 정보 추출

**상황**: FTP와 Telnet이 사용된 흔적이 있는 PCAP 파일에서 계정 정보가 노출되었는지 확인합니다.

**LLM에게 요청**:
```
legacy_traffic.pcap에서 평문으로 전송된 계정 정보가 있는지 확인해줘.
```

**`extract_credentials` 도구 실행 결과 예시**:
```
Analyzed PCAP: legacy_traffic.pcap

Plaintext Credentials:
FTP: admin:P@ssw0rd123 (Frame 42)
FTP: backup:backup2024 (Frame 87)
HTTP Basic Auth: webmaster:secretkey (Frame 134)
Telnet: root:toor (Frame 201)

Encrypted/Hashed Credentials:
Kerberos: User=jsmith Realm=CORP.LOCAL (Frame 310)
Hash=$krb5asrep$23$jsmith@CORP.LOCAL$a3f9...
Cracking Command: hashcat -m 18200
```

**LLM 분석 결과**:
> FTP와 Telnet을 통해 총 4개의 계정 정보가 평문으로 노출되었습니다. 특히 `root:toor`는 기본 비밀번호로, 즉시 변경이 필요합니다. Kerberos 해시도 추출되었으며 hashcat으로 크래킹 시도가 가능한 상태입니다. FTP/Telnet을 SFTP/SSH로 전환하고 모든 노출된 계정의 비밀번호를 즉시 변경하시기 바랍니다.

---

### 사례 5: IP 위협 정보 조회

**상황**: 방화벽 로그에서 수상한 IP `185.220.101.45`를 발견했습니다.

**LLM에게 요청**:
```
185.220.101.45 이 IP가 알려진 악성 IP인지 확인해줘.
```

**`check_ip_threats` 도구 실행 결과 예시**:
```
IP checked: 185.220.101.45

Threat check against URLhaus blacklist:
Potential threat detected in URLhaus blacklist.
```

**LLM 분석 결과**:
> 185.220.101.45는 URLhaus 블랙리스트에 등록된 악성 IP입니다. 이 IP는 멀웨어 배포 또는 피싱 사이트 호스팅에 연루된 것으로 알려져 있습니다. 방화벽에서 즉시 차단하고, 내부 호스트 중 해당 IP와 통신한 기록이 있는지 전수 조사하시기 바랍니다.

---

## 활용 팁

- **인터페이스 확인**: `capture_packets` 사용 전 `tshark -D` 명령으로 사용 가능한 인터페이스 목록을 확인하세요. macOS는 보통 `en0`, Linux는 `eth0` 또는 `ens3`입니다.
- **관리자 권한**: 패킷 캡처는 관리자(root/sudo) 권한이 필요합니다. Claude Desktop이나 Cursor 실행 시 권한 문제가 발생하면 관리자로 실행하세요.
- **캡처 시간**: `duration` 기본값은 5초입니다. 트래픽이 적은 환경에서는 10~30초로 늘려보세요.
- **PCAP 파일 경로**: `analyze_pcap`과 `extract_credentials`에는 절대 경로 사용을 권장합니다.

---

## 라이선스

[MIT](LICENSE)
