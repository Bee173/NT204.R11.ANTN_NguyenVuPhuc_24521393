# Kết quả kiểm thử Bài tập 1

Tài liệu này tổng hợp các kịch bản kiểm thử cho module Packet Capture & Parser. Mỗi kịch bản có script tạo PCAP, dữ liệu PCAP, kết quả JSON Lines và script xác minh trong thư mục tương ứng.

## Tổng quan kết quả

- Số kịch bản bắt buộc: **12**.
- Số kịch bản thành công: **12/12**.
- Kết luận: **PASS - đáp ứng toàn bộ test case bắt buộc của Bài tập 1**.
- Kết quả được xác minh bằng cách chạy lại trực tiếp các lệnh bên dưới.

## Chi tiết kịch bản

| STT | Thư mục | Kịch bản và dữ liệu vào | Kết quả mong đợi | Kết quả thực tế |
|---:|---|---|---|---|
| 1 | `TCP_handshake` | Ba packet TCP: SYN, SYN/ACK, ACK | Nhận diện đúng ba trạng thái của quá trình bắt tay | **PASS** |
| 2 | `TCP_data` | TCP packet có payload | Parse đúng TCP và độ dài payload | **PASS** |
| 3 | `UDP` | UDP packet có payload | Parse đúng địa chỉ, port và độ dài payload | **PASS** |
| 4 | `HTTP_GET` | HTTP GET trên port không chuẩn `9000` | Nhận diện HTTP bằng payload và parse request | **PASS** |
| 5 | `HTTP_POST` | HTTP POST có header và body | Parse đúng method, path, header và body | **PASS** |
| 6 | `HTTP_response` | HTTP response `200 OK` | Parse đúng status code, reason và header | **PASS** |
| 7 | `DNS_query` | DNS query cho `example.com`, type A | Parse đúng domain và query type | **PASS** |
| 8 | `DNS_response` | DNS response có bản ghi A | Parse được ít nhất một answer và địa chỉ IP | **PASS** |
| 9 | `SMTP_command` | Các lệnh EHLO, MAIL FROM và RCPT TO | Nhận diện và parse đúng SMTP command | **PASS** |
| 10 | `SMTP_response` | SMTP response `250 OK` | Parse đúng status code và message | **PASS** |
| 11 | `Unknown_protocol` | Packet không thuộc application protocol được hỗ trợ | Đánh dấu `UNKNOWN`, chương trình không crash | **PASS** |
| 12 | `Malformed_packet` | Packet thiếu hoặc có cấu trúc không đầy đủ | Chương trình tiếp tục chạy và tạo event an toàn | **PASS** |

## Cấu trúc của một thư mục test

```text
<tên_test>/
├── generate_pcap.py  # Tạo dữ liệu PCAP tái hiện kịch bản
├── <tên_test>.pcap   # Dữ liệu packet đầu vào
├── result.jsonl      # Event do pipeline tạo ra
├── flows.jsonl       # Flow được xuất sau khi xử lý
└── verify.py         # Kiểm tra kết quả và in PASS/FAIL
```

## Cách chạy lại một kịch bản

Ví dụ với TCP handshake, chạy từ thư mục gốc project:

```bash
python TEST/BT1/TCP_handshake/generate_pcap.py

python main.py \
  --pcap TEST/BT1/TCP_handshake/tcp_handshake.pcap \
  --output TEST/BT1/TCP_handshake/result.jsonl \
  --flow-output TEST/BT1/TCP_handshake/flows.jsonl

python TEST/BT1/TCP_handshake/verify.py
```

Kịch bản thành công khi lệnh cuối in thông báo bắt đầu bằng `PASS` và kết thúc với exit code `0`.

## Kiểm tra nhanh toàn bộ kết quả đã lưu

```bash
find TEST/BT1 -name verify.py -print | sort | while read -r test_file; do
  python "$test_file" || exit 1
done
```

Lệnh trên xác minh các file `result.jsonl` hiện có. Để tái tạo kết quả từ source hiện tại, chạy lần lượt `generate_pcap.py`, `main.py` và `verify.py` như ví dụ phía trên.

## Nhật ký chạy test (lệnh và kết quả thực tế)

Toàn bộ 12 test case dưới đây được chạy lại tuần tự từ thư mục gốc project. Output hiển thị nguyên văn từ terminal, không chỉnh sửa.

### 1. TCP_handshake

```bash
python TEST/BT1/TCP_handshake/generate_pcap.py
python main.py --pcap TEST/BT1/TCP_handshake/tcp_handshake.pcap --output TEST/BT1/TCP_handshake/result.jsonl --flow-output TEST/BT1/TCP_handshake/flows.jsonl
python TEST/BT1/TCP_handshake/verify.py
```

```text
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/TCP_handshake/tcp_handshake.pcap
Number of packets: 3
[1] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[2] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[3] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
PASS: TCP handshake was parsed correctly
TCP states: ['SYN', 'SYN/ACK', 'ACK']
```

### 2. TCP_data

```bash
python TEST/BT1/TCP_data/generate_pcap.py
python main.py --pcap TEST/BT1/TCP_data/tcp_data.pcap --output TEST/BT1/TCP_data/result.jsonl --flow-output TEST/BT1/TCP_data/flows.jsonl
python TEST/BT1/TCP_data/verify.py
```

```text
WARNING: getmacbyip failed on Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)
WARNING: MAC address to reach destination not found. Using broadcast.
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/TCP_data/tcp_data.pcap
Payload length: 9 bytes
[1] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
PASS: TCP data was parsed correctly
Payload length: 9 bytes
```

### 3. UDP

```bash
python TEST/BT1/UDP/generate_pcap.py
python main.py --pcap TEST/BT1/UDP/udp.pcap --output TEST/BT1/UDP/result.jsonl --flow-output TEST/BT1/UDP/flows.jsonl
python TEST/BT1/UDP/verify.py
```

```text
WARNING: getmacbyip failed on Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)
WARNING: MAC address to reach destination not found. Using broadcast.
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/UDP/udp.pcap
Payload length: 9 bytes
[1] 10.0.0.1 -> 10.0.0.2 UDP UNKNOWN
PASS: UDP packet was parsed correctly
Payload length: 9 bytes
```

### 4. HTTP_GET

```bash
python TEST/BT1/HTTP_GET/generate_pcap.py
python main.py --pcap TEST/BT1/HTTP_GET/http_get.pcap --output TEST/BT1/HTTP_GET/result.jsonl --flow-output TEST/BT1/HTTP_GET/flows.jsonl
python TEST/BT1/HTTP_GET/verify.py
```

```text
WARNING: getmacbyip failed on Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)
WARNING: MAC address to reach destination not found. Using broadcast.
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/HTTP_GET/http_get.pcap
HTTP method: GET
Destination port: 9000
[1] 10.0.0.1 -> 10.0.0.2 TCP HTTP
PASS: HTTP GET was parsed correctly
HTTP was detected on non-standard port 9000
```

### 5. HTTP_POST

```bash
python TEST/BT1/HTTP_POST/generate_pcap.py
python main.py --pcap TEST/BT1/HTTP_POST/http_post.pcap --output TEST/BT1/HTTP_POST/result.jsonl --flow-output TEST/BT1/HTTP_POST/flows.jsonl
python TEST/BT1/HTTP_POST/verify.py
```

```text
WARNING: getmacbyip failed on Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)
WARNING: MAC address to reach destination not found. Using broadcast.
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/HTTP_POST/http_post.pcap
Body: username=test&pass=1
Body length: 20 bytes
[1] 10.0.0.1 -> 10.0.0.2 TCP HTTP
PASS: HTTP POST was parsed correctly
Body: username=test&pass=1
```

### 6. HTTP_response

```bash
python TEST/BT1/HTTP_response/generate_pcap.py
python main.py --pcap TEST/BT1/HTTP_response/http_response.pcap --output TEST/BT1/HTTP_response/result.jsonl --flow-output TEST/BT1/HTTP_response/flows.jsonl
python TEST/BT1/HTTP_response/verify.py
```

```text
WARNING: getmacbyip failed on Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)
WARNING: MAC address to reach destination not found. Using broadcast.
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/HTTP_response/http_response.pcap
Status: 200 OK
[1] 10.0.0.2 -> 10.0.0.1 TCP HTTP
PASS: HTTP response was parsed correctly
Status: 200 OK
```

### 7. DNS_query

```bash
python TEST/BT1/DNS_query/generate_pcap.py
python main.py --pcap TEST/BT1/DNS_query/dns_query.pcap --output TEST/BT1/DNS_query/result.jsonl --flow-output TEST/BT1/DNS_query/flows.jsonl
python TEST/BT1/DNS_query/verify.py
```

```text
WARNING: getmacbyip failed on Permission denied: could not open /dev/bpf0. Make sure to be running Scapy as root ! (sudo)
WARNING: MAC address to reach destination not found. Using broadcast.
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/DNS_query/dns_query.pcap
Query: example.com
Query type: A
[1] 10.0.0.1 -> 8.8.8.8 UDP DNS
PASS: DNS query was parsed correctly
Query: example.com
Query type: A
```

### 8. DNS_response

```bash
python TEST/BT1/DNS_response/generate_pcap.py
python main.py --pcap TEST/BT1/DNS_response/dns_response.pcap --output TEST/BT1/DNS_response/result.jsonl --flow-output TEST/BT1/DNS_response/flows.jsonl
python TEST/BT1/DNS_response/verify.py
```

```text
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/DNS_response/dns_response.pcap
Answer: example.com -> 93.184.216.34
[1] 8.8.8.8 -> 10.0.0.1 UDP DNS
PASS: DNS response was parsed correctly
Answer: example.com -> 93.184.216.34
```

### 9. SMTP_command

```bash
python TEST/BT1/SMTP_command/generate_pcap.py
python main.py --pcap TEST/BT1/SMTP_command/smtp_command.pcap --output TEST/BT1/SMTP_command/result.jsonl --flow-output TEST/BT1/SMTP_command/flows.jsonl
python TEST/BT1/SMTP_command/verify.py
```

```text
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/SMTP_command/smtp_command.pcap
Commands: EHLO, MAIL FROM, RCPT TO
[1] 10.0.0.1 -> 10.0.0.2 TCP SMTP
[2] 10.0.0.1 -> 10.0.0.2 TCP SMTP
[3] 10.0.0.1 -> 10.0.0.2 TCP SMTP
PASS: SMTP commands were parsed correctly
Commands: EHLO, MAIL FROM, RCPT TO
```

### 10. SMTP_response

```bash
python TEST/BT1/SMTP_response/generate_pcap.py
python main.py --pcap TEST/BT1/SMTP_response/smtp_response.pcap --output TEST/BT1/SMTP_response/result.jsonl --flow-output TEST/BT1/SMTP_response/flows.jsonl
python TEST/BT1/SMTP_response/verify.py
```

```text
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/SMTP_response/smtp_response.pcap
SMTP response: 250 OK
[1] 10.0.0.2 -> 10.0.0.1 TCP SMTP
PASS: SMTP response was parsed correctly
Status: 250 OK
```

### 11. Unknown_protocol

```bash
python TEST/BT1/Unknown_protocol/generate_pcap.py
python main.py --pcap TEST/BT1/Unknown_protocol/unknown_protocol.pcap --output TEST/BT1/Unknown_protocol/result.jsonl --flow-output TEST/BT1/Unknown_protocol/flows.jsonl
python TEST/BT1/Unknown_protocol/verify.py
```

```text
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/Unknown_protocol/unknown_protocol.pcap
Protocol: ICMP
[1] 10.0.0.1 -> 10.0.0.2 UNKNOWN UNKNOWN
PASS: Unknown protocol was handled correctly
The program did not crash
```

### 12. Malformed_packet

```bash
python TEST/BT1/Malformed_packet/generate_pcap.py
python main.py --pcap TEST/BT1/Malformed_packet/malformed_packet.pcap --output TEST/BT1/Malformed_packet/result.jsonl --flow-output TEST/BT1/Malformed_packet/flows.jsonl
python TEST/BT1/Malformed_packet/verify.py
```

```text
Created: /Users/ber/Desktop/UIT/NT204.R11.ANTN/TEST/BT1/Malformed_packet/malformed_packet.pcap
Packet length: 18 bytes
The IPv4 header is intentionally truncated
[1] None -> None UNKNOWN UNKNOWN
PASS: Malformed packet was handled correctly
The program did not crash
Parse errors: []
```

**Tổng kết: 12/12 PASS**, khớp với bảng tổng quan ở trên. Hai dòng `WARNING: getmacbyip ...` xuất hiện ở một số `generate_pcap.py` do Scapy cố gắng resolve MAC khi không chạy quyền root trên macOS; đây là cảnh báo của Scapy khi tạo PCAP giả lập, không ảnh hưởng tới kết quả parser và không xuất hiện ở `main.py`/`verify.py`.
