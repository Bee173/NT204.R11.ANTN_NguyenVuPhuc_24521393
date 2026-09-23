# PACKET CAPTURE & PARSER CHO HỆ THỐNG IDS

Module thu thập packet từ network interface hoặc file PCAP, phân tích IPv4, TCP, UDP, HTTP, DNS và SMTP, sau đó ghi kết quả chuẩn hóa theo định dạng JSON Lines.

## Cài đặt

Yêu cầu Python 3 và Scapy:

```bash
python -m pip install scapy
```

## Cách sử dụng

Chạy các lệnh từ thư mục `BT1`.

Đọc packet từ file PCAP:

```bash
python main.py --pcap <duong_dan_file.pcap>
```

Bắt packet trực tiếp trên macOS:

```bash
sudo "$(which python)" main.py --interface en0 --count 10
```

Chỉ định file kết quả:

```bash
python main.py --pcap test.pcap --output output/events.jsonl
```

Mỗi dòng trong file output là một JSON event đã được chuẩn hóa.

## Các test case

| Test case | Nội dung kiểm tra |
|---|---|
| TCP Handshake | Nhận diện SYN, SYN/ACK và ACK |
| TCP Data | Phân tích TCP packet có payload |
| UDP | Phân tích UDP packet |
| HTTP GET | Phân tích GET trên cổng không chuẩn 9000 |
| HTTP POST | Phân tích POST và body |
| HTTP Response | Phân tích status code, header và body |
| DNS Query | Phân tích domain và query type |
| DNS Response | Phân tích DNS answer |
| SMTP Command | Phân tích EHLO, MAIL FROM và RCPT TO |
| SMTP Response | Phân tích SMTP status code |
| Unknown Protocol | Xử lý giao thức chưa hỗ trợ mà không crash |
| Malformed Packet | Xử lý packet bị cắt ngắn mà không crash |

Mỗi thư mục trong `TEST` gồm dữ liệu PCAP, kết quả `result.jsonl`, chương trình tạo dữ liệu và chương trình kiểm tra. Ví dụ:

```bash
python TEST/HTTP_GET/generate_pcap.py
python main.py --pcap TEST/HTTP_GET/http_get.pcap --output TEST/HTTP_GET/result.jsonl
python TEST/HTTP_GET/verify.py
```

## Khai báo sử dụng AI

- **Công cụ sử dụng:** ChatGPT.

- **Mục đích sử dụng:** Hỗ trợ tìm hiểu yêu cầu, gợi ý cách xây dựng chương trình, viết mã nguồn, tạo các trường hợp kiểm thử và kiểm tra lỗi.

- **Phần mã nguồn có sử dụng AI:** AI được sử dụng trong quá trình xây dựng và rà soát các thành phần của bài tập, gồm `main.py`, thư mục `src` và `TEST`. Trực tiếp tích hợp, điều chỉnh, chạy từng trường hợp kiểm thử và kiểm tra kết quả trước khi nộp.