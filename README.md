# IDS — Packet Parser, Decoder, Preprocessor và Flow Tracker

Chương trình thu thập packet từ network interface hoặc file PCAP, phân tích giao thức, giải mã dữ liệu, chuẩn hóa event và theo dõi flow hai chiều.

Toàn bộ bài tập dùng chung một chương trình với điểm chạy chính là `main.py`.

## 1. Luồng xử lý

Packet Capture → Parser → Decoder → Preprocessor → Flow Tracker → JSONL

| Thành phần | Chức năng |
|---|---|
| Packet Capture | Thu thập packet trực tiếp hoặc đọc từ PCAP |
| Parser | Phân tích IPv4, TCP, UDP, HTTP, DNS và SMTP |
| Decoder | Giải mã URL, HTTP form, HTML entity và SMTP/MIME |
| Preprocessor | Kiểm tra field, chuẩn hóa dữ liệu và xác định chính sách xử lý |
| Flow Tracker | Gom packet hai chiều, theo dõi trạng thái, thống kê và timeout |
| Logger | Ghi event và flow theo định dạng JSON Lines |

## 2. Cấu trúc project

```text
NT204.R11.ANTN/
├── main.py
├── src/
│   ├── capture.py
│   ├── pipeline.py
│   ├── normalized.py
│   ├── decoder.py
│   ├── preprocessor.py
│   ├── flow_tracker.py
│   ├── logger.py
│   └── parsers/
│       ├── network.py
│       ├── transport.py
│       ├── application_detector.py
│       └── application/
│           ├── http.py
│           ├── dns.py
│           └── smtp.py
├── TEST/
│   ├── BT1/
│   └── BT2/
├── output/
└── README.md
```

`TEST/BT1` và `TEST/BT2` phân nhóm dữ liệu và script kiểm thử.
Các test dùng chung chương trình ở thư mục gốc.

## 3. Cài đặt

Yêu cầu Python 3.10 trở lên và Scapy:

```bash
python -m pip install scapy
```

Chạy các lệnh dưới đây tại thư mục gốc project, nơi chứa `main.py`.

## 4. Cách sử dụng

### Đọc file PCAP

```bash
python main.py \
  --pcap TEST/BT2/T09_TCP_handshake/tcp_handshake.pcap \
  --output output/events.jsonl \
  --flow-output output/flows.jsonl
```

### Bắt packet trực tiếp trên macOS

```bash
sudo "$(which python)" main.py \
  --interface en0 \
  --count 20 \
  --output output/events.jsonl \
  --flow-output output/flows.jsonl
```

Thay `en0` bằng interface thực tế của máy.
`--count 0` cho phép bắt liên tục; nhấn `Ctrl + C` để dừng.

### Cấu hình xử lý

```bash
python main.py \
  --pcap TEST/BT2/T10_UDP_bidirectional/udp_dns.pcap \
  --tcp-timeout 120 \
  --udp-timeout 30 \
  --max-decode-bytes 1048576 \
  --max-form-fields 1000 \
  --output output/events.jsonl \
  --flow-output output/flows.jsonl
```

| Tham số | Mặc định | Ý nghĩa |
|---|---|---|
| `--interface` | Không có | Interface để bắt packet trực tiếp |
| `--pcap` | Không có | File PCAP đầu vào |
| `--output` | `output/events.jsonl` | File event |
| `--flow-output` | `output/flows.jsonl` | File flow được xuất |
| `--count` | `0` | Giới hạn packet khi bắt trực tiếp |
| `--tcp-timeout` | `120` giây | Idle timeout của TCP |
| `--udp-timeout` | `30` giây | Idle timeout của UDP |
| `--max-decode-bytes` | `1048576` byte | Giới hạn payload đưa vào Decoder |
| `--max-form-fields` | `1000` | Giới hạn số field HTTP form |
| `--allow-invalid` | Không bật | Cho phép event invalid tiếp tục; Tracker vẫn kiểm tra dữ liệu |
| `--allow-unsupported` | Không bật | Cho phép protocol chưa hỗ trợ tiếp tục; Tracker chỉ theo dõi TCP/UDP |

Chọn một trong hai nguồn `--interface` hoặc `--pcap`.
File event và file flow phải khác nhau.

Mỗi lần chạy, các file output được làm trống trước khi ghi kết quả mới.

## 5. Decoder

Các chức năng:

- HTTP URL/percent decoding.
- HTTP form decoding khi Content-Type là `application/x-www-form-urlencoded`.
- HTML entity decoding trong HTTP body có Content-Type `text/html` hoặc `text/plain`.
- SMTP/MIME Base64 và Quoted-Printable theo header `Content-Transfer-Encoding`.
- Ghi nhận lỗi character decoding và lỗi dữ liệu đầu vào.

Dữ liệu gốc được giữ cùng dữ liệu đã giải mã:

| Field | Nội dung |
|---|---|
| `application.path` | URI gốc |
| `application.decoded_path` | URI đã percent-decode |
| `application.body` | HTTP body trước bước Decoder |
| `application.decoded_form` | Danh sách cặp tên–giá trị của HTTP form |
| `application.decoded_body` | Body đã giải mã |
| `application.raw_payload_b64` | Biểu diễn Base64 của payload bytes gốc |
| `decode_status` | `success`, `partial`, `error` hoặc `skipped` |
| `decode_errors` | Danh sách lỗi hoặc lý do bỏ qua decode |

HTTP form dùng danh sách cặp để giữ field trùng tên và giá trị rỗng.

`raw_payload_b64` là cách lưu bytes trong JSON, không phải encoding MIME của nội dung email.

## 6. Preprocessor

Preprocessor thực hiện:

- Chuẩn hóa tên transport/application protocol thành chữ hoa.
- Kiểm tra và chuẩn hóa IP.
- Kiểm tra port trong khoảng `0–65535`.
- Chuẩn hóa timestamp thành Unix seconds dạng số, hữu hạn và không âm.
- Kiểm tra độ dài packet/payload.
- Chuẩn hóa tên HTTP header thành chữ thường.
- Chuẩn hóa DNS query và bổ sung biểu diễn HTTP Host chữ thường.
- Giữ nguyên chữ hoa/thường của HTTP path.
- Chuẩn hóa object/list thiếu thành `{}` hoặc `[]`; field đơn thiếu dùng `null`.

Các field trạng thái:

| Field | Ý nghĩa |
|---|---|
| `preprocess_status` | `valid`, `partial` hoặc `invalid` |
| `processing_action` | `continue` hoặc `skip` |
| `reason` | Danh sách lý do xử lý |

`skip` là chỉ dẫn để bỏ qua bước tracking; event vẫn được ghi log.

Các field cần thiết để tạo flow, như IP, port, timestamp và packet length, được kiểm tra trước khi cập nhật thống kê.

## 7. Flow/Connection Tracker

### Nhận diện flow hai chiều

Flow được nhận diện bằng protocol và hai endpoint IP/port.
Hai chiều A→B và B→A thuộc cùng một flow.

Endpoint A/B được sắp xếp nhất quán:

- `forward`: A→B.
- `backward`: B→A.
- Endpoint A không nhất thiết là client.

`flow_id` được tạo từ key hai chiều, timestamp bắt đầu và số phiên riêng của key.
Flow khác không làm thay đổi số phiên của key này.
Phiên mới dùng lại cùng 5-tuple có định danh riêng.

### TCP state

| State | Ý nghĩa |
|---|---|
| `NEW` | Flow vừa được tạo, chưa ghi nhận handshake đầy đủ |
| `HANDSHAKE` | Đang theo dõi SYN và SYN/ACK |
| `ESTABLISHED` | Đã ghi nhận SYN → SYN/ACK → ACK đúng chiều |
| `CLOSING` | Đã ghi nhận FIN, đang theo dõi đóng kết nối |
| `CLOSED` | FIN của cả hai chiều đã được ACK |
| `RESET` | Đã ghi nhận RST |

TCP packet không có payload vẫn được theo dõi và tính vào thống kê.

### UDP và timeout

UDP dùng state `ACTIVE` trong thời gian flow còn hoạt động.

- TCP và UDP có timeout riêng.
- Flow hết hạn khi thời gian im lặng lớn hơn timeout.
- PCAP dùng timestamp của packet để xét timeout.
- Bắt trực tiếp kiểm tra timeout định kỳ, kể cả khi không có packet mới.
- Flow CLOSED/RESET hoặc hết hạn được xuất và xóa khỏi active table.
- Khi kết thúc capture, các flow còn lại được xuất.

Flow hết hạn có state `EXPIRED` và lưu trạng thái trước đó trong `state_before_export`.

### Thống kê flow

| Nhóm | Fields |
|---|---|
| Định danh | `flow_id`, `protocol`, `application_protocol`, `endpoint_a`, `endpoint_b` |
| Thời gian | `start_time`, `last_seen`, `duration` |
| Tổng thể | `packet_count`, `byte_count` |
| Hai chiều | `forward_packet_count`, `backward_packet_count`, `forward_byte_count`, `backward_byte_count` |
| TCP | `SYN_count`, `ACK_count`, `FIN_count`, `RST_count`, `state` |

Quy ước:

- `byte_count` là tổng `len(packet)`, gồm các header hiện diện trong packet.
- `duration = last_seen - start_time`.
- Một packet SYN/ACK tăng cả `SYN_count` và `ACK_count`.
- Event lưu snapshot flow tại thời điểm xử lý; packet sau không sửa snapshot trước.

## 8. Output

### Event output

Mỗi dòng trong `events.jsonl` là một event, gồm:

- Thông tin packet và kết quả parser.
- Dữ liệu decoded và trạng thái decode.
- Trạng thái preprocessing và lý do xử lý.
- `flow_id`, `direction`, `track_status`.
- Snapshot `flow` nếu packet được tracking.
- `track_reason` khi tracking gặp dữ liệu không hợp lệ.

### Flow output

Mỗi dòng trong `flows.jsonl` là một flow đã được xuất.

| `export_reason` | Ý nghĩa |
|---|---|
| `connection_closed` | TCP CLOSED hoặc RESET |
| `idle_timeout` | Flow hết hạn do không có packet mới |
| `capture_end` | Xuất flow còn lại khi kết thúc capture |

## 9. Kiểm thử

### BT1

Các nhóm test parser nằm trong `TEST/BT1`:

- TCP handshake và TCP data.
- UDP.
- HTTP GET, POST và response.
- DNS query và response.
- SMTP command và response.
- Unknown protocol và malformed packet.

Test HTTP kiểm tra header name ở dạng chữ thường, phù hợp output sau Preprocessor.

### BT2 và ánh xạ với đề

Số thứ tự thư mục được đặt theo thứ tự triển khai, nên có một số khác biệt với ID trong đề.

| Thư mục trong `TEST/BT2` | Nội dung | ID trong đề |
|---|---|---|
| `T01_HTTP_URL_decode` | Percent-decode URI, giữ URI gốc | T01 |
| `T02_HTTP_form_decode` | HTTP form, field trùng tên và giá trị rỗng | Bổ sung yêu cầu HTTP form |
| `T03_HTML_entity` | HTML entity decoding | T02 |
| `T04_SMTP_MIME` | SMTP Base64 và Quoted-Printable | T03 |
| `T05_Invalid_bytes` | UTF-8 lỗi, tiếp tục xử lý packet sau | T04 |
| `T06_Normalization` | Chuẩn hóa protocol, IP, port, timestamp, header và domain | T05 |
| `T07_Missing_field` | Field không bắt buộc bị thiếu hoặc null | T06 |
| `T08_Malformed_event` | Event lỗi, protocol chưa hỗ trợ và chính sách bỏ qua | T14 |
| `T09_TCP_handshake` | Handshake, cùng flow và direction hai chiều | T07, T08 |
| `T10_UDP_bidirectional` | DNS UDP query/response hai chiều | T08, T10 |
| `T11_Concurrent_flows` | Tách các flow xen kẽ, khác IP/port/protocol | T11 |
| `T12_TCP_close` | FIN close và RST | T09 |
| `T13_Idle_timeout` | Timeout, giải phóng bảng và phiên mới | T12 |
| `T14_Statistics` | Packet/byte/flag counters, duration và snapshot | T13 |

Các test dựa trên PCAP có script tạo dữ liệu, file PCAP, kết quả JSONL và `verify.py`.
Các test dùng event trực tiếp hoặc thời gian giả lập không cần PCAP.

### Ví dụ chạy test PCAP

```bash
python TEST/BT2/T09_TCP_handshake/generate_pcap.py

python main.py \
  --pcap TEST/BT2/T09_TCP_handshake/tcp_handshake.pcap \
  --output TEST/BT2/T09_TCP_handshake/result.jsonl \
  --flow-output TEST/BT2/T09_TCP_handshake/flows.jsonl

python TEST/BT2/T09_TCP_handshake/verify.py
```

### Ví dụ chạy test event trực tiếp

```bash
python TEST/BT2/T08_Malformed_event/verify.py
python TEST/BT2/T13_Idle_timeout/verify.py
```

## 10. Giới hạn hiện tại

- Parser network hiện hỗ trợ IPv4.
- Không giải mã HTTPS/TLS, DoH/DoT hoặc dữ liệu mã hóa bằng mật mã.
- HTTP character decoding hiện dùng UTF-8; ASCII hợp lệ cũng được chấp nhận.
- SMTP/MIME hỗ trợ message đầy đủ trong một packet; chưa ghép TCP stream và chưa hỗ trợ MIME multipart.
- TCP tracking là trạng thái logic tối thiểu, chưa xác thực đầy đủ sequence/ACK của handshake.
- Protocol ứng dụng có thể được suy đoán theo port khi không có payload.
- Giới hạn Decoder được áp dụng sau parser, không phải giới hạn bộ nhớ toàn pipeline.

## 11. Khai báo sử dụng AI

- **Công cụ:** ChatGPT.
- **Mục đích:** Hỗ trợ phân tích yêu cầu, thiết kế module, giải thích code, viết code, tạo test và rà soát lỗi.
- **Phần có sử dụng AI:** `main.py`, các module trong `src`, script kiểm thử trong `TEST` và nội dung README.
- Người nộp có trách nhiệm kiểm tra kết quả chạy thực tế, hiểu và giải thích được mã nguồn đã nộp.