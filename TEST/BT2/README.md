# Kết quả kiểm thử Bài tập 2

Tài liệu này tổng hợp các kịch bản kiểm thử cho Decoder, Preprocessor và Flow/Connection Tracker. ID trong bảng bám theo đề bài; tên thư mục phản ánh thứ tự triển khai trong project.

## Tổng quan kết quả

- Số test case bắt buộc theo đề: **14**.
- Test bổ sung cho HTTP form decoding: **1**.
- Số test case thành công: **15/15**.
- Kết luận: **PASS - toàn bộ kịch bản hiện có đều thành công**.
- Kết quả được xác minh bằng cách chạy lại trực tiếp các lệnh bên dưới.

## Chi tiết kịch bản

| ID đề bài | Thư mục | Kịch bản và dữ liệu vào | Kết quả mong đợi | Kết quả thực tế |
|---|---|---|---|---|
| T01 | `T01_HTTP_URL_decode` | URI chứa percent-encoding | `decoded_path` đúng và `path` gốc được giữ nguyên | **PASS** |
| Bổ sung | `T02_HTTP_form_decode` | Form URL-encoded có dấu `+`, percent-encoding, field trùng và giá trị rỗng | Decode đúng và không làm mất field trùng hoặc body gốc | **PASS** |
| T02 | `T03_HTML_entity` | HTTP text chứa HTML entity như `&lt;...&gt;` | Tạo decoded text đúng và giữ body gốc | **PASS** |
| T03 | `T04_SMTP_MIME` | Hai MIME message dùng Base64 và Quoted-Printable | Decode đúng body và ghi `decode_status` | **PASS** |
| T04 | `T05_Invalid_bytes` | HTTP payload chứa byte không hợp lệ UTF-8, sau đó là packet hợp lệ | Đánh dấu lỗi/partial, giữ raw bytes và tiếp tục xử lý | **PASS** |
| T05 | `T06_Normalization` | Protocol, IP, port, timestamp, HTTP header và DNS domain khác format | Biểu diễn sau preprocess nhất quán | **PASS** |
| T06 | `T07_Missing_field` | HTTP/DNS event thiếu field không bắt buộc hoặc dùng `null` | Chuẩn hóa thành `null`, `{}` hoặc `[]`, không exception | **PASS** |
| T07 | `T09_TCP_handshake` | SYN → SYN/ACK → ACK | Một flow và trạng thái cuối `ESTABLISHED` | **PASS** |
| T08 | `T09_TCP_handshake`, `T10_UDP_bidirectional` | Packet TCP và UDP theo cả hai chiều A→B, B→A | Mỗi cặp hai chiều có cùng `flow_id` và direction đúng | **PASS** |
| T09 | `T12_TCP_close` | Đóng bằng FIN/ACK và kết thúc bằng RST | Flow chuyển `CLOSED` hoặc `RESET` phù hợp | **PASS** |
| T10 | `T10_UDP_bidirectional` | DNS UDP query và response | Một UDP flow, packet/byte counters đúng | **PASS** |
| T11 | `T11_Concurrent_flows` | Bốn flow xen kẽ, khác endpoint, port hoặc protocol | Không gộp nhầm flow | **PASS** |
| T12 | `T13_Idle_timeout` | TCP/UDP flow không có packet mới quá timeout | Xuất flow hết hạn và xóa khỏi active table | **PASS** |
| T13 | `T14_Statistics` | Nhiều TCP packet hai chiều, có data và FIN | Counters, flags, byte count và duration đúng | **PASS** |
| T14 | `T08_Malformed_event` | IP/port/timestamp sai, protocol unsupported, object sai kiểu và event không phải dictionary | Không crash; status, action và reason phù hợp | **PASS** |

## Phạm vi của từng nhóm

### Decoder

- Percent decoding cho HTTP URI.
- HTTP `application/x-www-form-urlencoded`.
- HTML entity decoding.
- SMTP/MIME Base64 và Quoted-Printable.
- Phát hiện byte UTF-8 lỗi trong HTTP và giữ raw payload dưới dạng Base64.

### Preprocessor

- Chuẩn hóa transport/application protocol, IP, port và timestamp.
- Chuẩn hóa HTTP header, HTTP Host và DNS query.
- Chuẩn hóa field thiếu thành `null`, `{}` hoặc `[]`.
- Gắn `preprocess_status`, `processing_action` và `reason`.

### Flow/Connection Tracker

- Gom packet hai chiều theo canonical 5-tuple.
- Gắn `flow_id` và direction ổn định trong cùng flow.
- Theo dõi TCP handshake, FIN close và RST.
- Theo dõi UDP flow và idle timeout riêng cho TCP/UDP.
- Thống kê packet, byte, hai chiều và TCP flags.
- Xuất và giải phóng flow khi đóng, timeout hoặc kết thúc capture.

## Cách chạy lại test dùng PCAP

Ví dụ với TCP handshake, chạy từ thư mục gốc project:

```bash
python TEST/BT2/T09_TCP_handshake/generate_pcap.py

python main.py \
  --pcap TEST/BT2/T09_TCP_handshake/tcp_handshake.pcap \
  --output TEST/BT2/T09_TCP_handshake/result.jsonl \
  --flow-output TEST/BT2/T09_TCP_handshake/flows.jsonl

python TEST/BT2/T09_TCP_handshake/verify.py
```

## Cách chạy test dùng event hoặc thời gian giả lập

Các test sau tự tạo input trong code và không cần chạy `main.py` trước:

```bash
python TEST/BT2/T06_Normalization/verify.py
python TEST/BT2/T07_Missing_field/verify.py
python TEST/BT2/T08_Malformed_event/verify.py
python TEST/BT2/T13_Idle_timeout/verify.py
```

## Kiểm tra nhanh toàn bộ kết quả

```bash
find TEST/BT2 -name verify.py -print | sort | while read -r test_file; do
  python "$test_file" || exit 1
done
```

Kịch bản thành công khi verifier in thông báo bắt đầu bằng `PASS` và kết thúc với exit code `0`. Với test PCAP, nên chạy lại đủ ba bước tạo PCAP, chạy pipeline và verify để xác nhận source hiện tại.

## Nhật ký chạy test (lệnh và kết quả thực tế)

Toàn bộ 14 test case dưới đây đã được chạy lại từ đầu (tạo PCAP mới nếu cần, chạy `main.py`, chạy `verify.py`) tại thư mục gốc project. Kết quả in dưới đây là nguyên văn output terminal, dùng làm bằng chứng thay cho ảnh chụp màn hình (đã lược bỏ dòng cảnh báo `WARNING: getmacbyip failed...` của Scapy do môi trường macOS không chạy packet capture bằng quyền root; dòng này không ảnh hưởng tới nội dung PCAP hay kết quả test).

### T01 — HTTP URL decode

```bash
python TEST/BT2/T01_HTTP_URL_decode/generate_pcap.py
python main.py --pcap TEST/BT2/T01_HTTP_URL_decode/http_url_decode.pcap \
  --output TEST/BT2/T01_HTTP_URL_decode/result.jsonl \
  --flow-output TEST/BT2/T01_HTTP_URL_decode/flows.jsonl
python TEST/BT2/T01_HTTP_URL_decode/verify.py
```

```text
Created http_url_decode.pcap
[1] 10.0.0.1 -> 10.0.0.2 TCP HTTP
PASS T01: decoded URI đúng, raw URI giữ nguyên
```

### Bổ sung — HTTP form decode

```bash
python TEST/BT2/T02_HTTP_form_decode/generate_pcap.py
python main.py --pcap TEST/BT2/T02_HTTP_form_decode/http_form_decode.pcap \
  --output TEST/BT2/T02_HTTP_form_decode/result.jsonl \
  --flow-output TEST/BT2/T02_HTTP_form_decode/flows.jsonl
python TEST/BT2/T02_HTTP_form_decode/verify.py
```

```text
Created http_form_decode.pcap
[1] 10.0.0.1 -> 10.0.0.2 TCP HTTP
PASS: HTTP form decoding
- Dấu + chuyển thành khoảng trắng
- Percent-encoding giải mã đúng
- Giữ field trùng tên và giá trị rỗng
- Body gốc giữ nguyên
```

### T02 — HTML entity

```bash
python TEST/BT2/T03_HTML_entity/generate_pcap.py
python main.py --pcap TEST/BT2/T03_HTML_entity/html_entity.pcap \
  --output TEST/BT2/T03_HTML_entity/result.jsonl \
  --flow-output TEST/BT2/T03_HTML_entity/flows.jsonl
python TEST/BT2/T03_HTML_entity/verify.py
```

```text
Created html_entity.pcap
[1] 10.0.0.2 -> 10.0.0.1 TCP HTTP
PASS T03: HTML entity giải mã đúng, body gốc giữ nguyên
```

### T03 — SMTP Base64/Quoted-Printable

```bash
python TEST/BT2/T04_SMTP_MIME/generate_pcap.py
python main.py --pcap TEST/BT2/T04_SMTP_MIME/smtp_mime.pcap \
  --output TEST/BT2/T04_SMTP_MIME/result.jsonl \
  --flow-output TEST/BT2/T04_SMTP_MIME/flows.jsonl
python TEST/BT2/T04_SMTP_MIME/verify.py
```

```text
Created smtp_mime.pcap: Base64 and Quoted-Printable
[1] 10.0.0.1 -> 10.0.0.2 TCP SMTP
[2] 10.0.0.1 -> 10.0.0.2 TCP SMTP
PASS T04: SMTP Base64 và Quoted-Printable
```

### T04 — Invalid bytes

```bash
python TEST/BT2/T05_Invalid_bytes/generate_pcap.py
python main.py --pcap TEST/BT2/T05_Invalid_bytes/invalid_bytes.pcap \
  --output TEST/BT2/T05_Invalid_bytes/result.jsonl \
  --flow-output TEST/BT2/T05_Invalid_bytes/flows.jsonl
python TEST/BT2/T05_Invalid_bytes/verify.py
```

```text
Created invalid_bytes.pcap
[1] 10.0.0.2 -> 10.0.0.1 TCP HTTP
[2] 10.0.0.2 -> 10.0.0.1 TCP HTTP
PASS T05: ghi nhận UTF-8 lỗi, giữ raw bytes, xử lý tiếp packet tốt
```

### T05 — Normalization

```bash
python TEST/BT2/T06_Normalization/verify.py
```

```text
PASS T06: protocol, IP, port, timestamp, header và domain
```

### T06 — Missing field

```bash
python TEST/BT2/T07_Missing_field/verify.py
```

```text
PASS T07: thiếu field không bắt buộc vẫn xử lý an toàn
- HTTP: headers={}, path/body/normalized_host=null
- DNS: query=null, answers=[]
- parse_errors/decode_errors=[]
```

### T07 + T08 — TCP handshake và bidirectional flow

```bash
python TEST/BT2/T09_TCP_handshake/generate_pcap.py
python main.py --pcap TEST/BT2/T09_TCP_handshake/tcp_handshake.pcap \
  --output TEST/BT2/T09_TCP_handshake/result.jsonl \
  --flow-output TEST/BT2/T09_TCP_handshake/flows.jsonl
python TEST/BT2/T09_TCP_handshake/verify.py
```

```text
Created tcp_handshake.pcap
[1] 10.0.0.1 -> 10.0.0.2 TCP HTTP
[2] 10.0.0.2 -> 10.0.0.1 TCP HTTP
[3] 10.0.0.1 -> 10.0.0.2 TCP HTTP
PASS T09: một flow hai chiều, ESTABLISHED, counters đúng
```

### T09 — TCP close

```bash
python TEST/BT2/T12_TCP_close/generate_pcap.py
python main.py --pcap TEST/BT2/T12_TCP_close/tcp_close.pcap \
  --output TEST/BT2/T12_TCP_close/result.jsonl \
  --flow-output TEST/BT2/T12_TCP_close/flows.jsonl
python TEST/BT2/T12_TCP_close/verify.py
```

```text
Created tcp_close.pcap: FIN close and RST
[1] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[2] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[3] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[4] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[5] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[6] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[7] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[8] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[9] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[10] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[11] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
PASS T12: FIN hai chiều → CLOSED; RST → RESET
```

### T10 — UDP query/response

```bash
python TEST/BT2/T10_UDP_bidirectional/generate_pcap.py
python main.py --pcap TEST/BT2/T10_UDP_bidirectional/udp_dns.pcap \
  --output TEST/BT2/T10_UDP_bidirectional/result.jsonl \
  --flow-output TEST/BT2/T10_UDP_bidirectional/flows.jsonl
python TEST/BT2/T10_UDP_bidirectional/verify.py
```

```text
Created udp_dns.pcap
[1] 10.0.0.1 -> 10.0.0.2 UDP DNS
[2] 10.0.0.2 -> 10.0.0.1 UDP DNS
PASS T10: DNS UDP hai chiều cùng flow, direction và thống kê đúng
```

### T11 — Concurrent flows

```bash
python TEST/BT2/T11_Concurrent_flows/generate_pcap.py
python main.py --pcap TEST/BT2/T11_Concurrent_flows/concurrent_flows.pcap \
  --output TEST/BT2/T11_Concurrent_flows/result.jsonl \
  --flow-output TEST/BT2/T11_Concurrent_flows/flows.jsonl
python TEST/BT2/T11_Concurrent_flows/verify.py
```

```text
Created concurrent_flows.pcap: 4 flows, 8 packets
[1] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[2] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[3] 10.0.0.1 -> 10.0.0.2 UDP UNKNOWN
[4] 10.0.0.1 -> 10.0.0.3 TCP UNKNOWN
[5] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[6] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[7] 10.0.0.2 -> 10.0.0.1 UDP UNKNOWN
[8] 10.0.0.3 -> 10.0.0.1 TCP UNKNOWN
PASS T11: 4 flow xen kẽ được tách đúng, hai chiều ghép đúng
```

### T12 — Idle timeout

```bash
python TEST/BT2/T13_Idle_timeout/verify.py
```

```text
PASS T13: TCP/UDP timeout, giải phóng bảng, ID phiên mới, flush
```

### T13 — Statistics

```bash
python TEST/BT2/T14_Statistics/generate_pcap.py
python main.py --pcap TEST/BT2/T14_Statistics/statistics.pcap \
  --output TEST/BT2/T14_Statistics/result.jsonl \
  --flow-output TEST/BT2/T14_Statistics/flows.jsonl
python TEST/BT2/T14_Statistics/verify.py
```

```text
Created statistics.pcap: 8 packets
[1] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[2] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[3] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[4] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[5] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[6] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
[7] 10.0.0.2 -> 10.0.0.1 TCP UNKNOWN
[8] 10.0.0.1 -> 10.0.0.2 TCP UNKNOWN
PASS T14: packet/byte/flags/duration và snapshot đúng
```

### T14 — Malformed event

```bash
python TEST/BT2/T08_Malformed_event/verify.py
```

```text
PASS: invalid_ip
PASS: port_too_large
PASS: negative_port
PASS: fractional_port
PASS: invalid_timestamp
PASS: infinite_timestamp
PASS: missing_required_ip
PASS: unsupported_skip
PASS: unsupported_continue
PASS: invalid_continue
PASS: malformed_application
PASS: non_dictionary
PASS: valid_after_errors
PASS T08: 13 cases
```

## Lưu ý về kết quả

Trạng thái `PASS` trong tài liệu phản ánh các kịch bản đã có trong repository. Các giới hạn đã biết của hệ thống, gồm SMTP/MIME trong một packet, chưa ghép TCP stream và giới hạn Decoder được áp dụng sau parser, được mô tả trong README ở thư mục gốc.
