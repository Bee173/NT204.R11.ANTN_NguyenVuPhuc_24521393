# Kết quả kiểm thử Bài tập 1

Tài liệu này tổng hợp các kịch bản kiểm thử cho module Packet Capture & Parser. Mỗi kịch bản có script tạo PCAP, dữ liệu PCAP, kết quả JSON Lines và script xác minh trong thư mục tương ứng.

## Tổng quan kết quả

- Số kịch bản bắt buộc: **12**.
- Số kịch bản thành công: **12/12**.
- Kết luận: **PASS - đáp ứng toàn bộ test case bắt buộc của Bài tập 1**.
- Lần xác minh gần nhất: **12/10/2026**.

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
