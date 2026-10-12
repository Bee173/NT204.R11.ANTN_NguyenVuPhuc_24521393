# Kết quả kiểm thử Bài tập 2

Tài liệu này tổng hợp các kịch bản kiểm thử cho Decoder, Preprocessor và Flow/Connection Tracker. ID trong bảng bám theo đề bài; tên thư mục phản ánh thứ tự triển khai trong project.

## Tổng quan kết quả

- Số test case bắt buộc theo đề: **14**.
- Test bổ sung cho HTTP form decoding: **1**.
- Số test case thành công: **15/15**.
- Kết luận: **PASS - toàn bộ kịch bản hiện có đều thành công**.
- Lần xác minh gần nhất: **12/10/2026**.

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

## Lưu ý về kết quả

Trạng thái `PASS` trong tài liệu phản ánh các kịch bản đã có trong repository. Các giới hạn đã biết của hệ thống, gồm SMTP/MIME trong một packet, chưa ghép TCP stream và giới hạn Decoder được áp dụng sau parser, được mô tả trong README ở thư mục gốc.
