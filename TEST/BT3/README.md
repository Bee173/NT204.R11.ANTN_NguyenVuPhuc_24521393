# Kết quả kiểm thử Bài tập 3

Tài liệu này tổng hợp các kịch bản kiểm thử cho Core Engine và Snort Rule Matching. Mỗi thư mục lưu rule/event input phù hợp, runner, kết quả JSON Lines và script xác minh để tái hiện test độc lập.

## Tổng quan kết quả

- Số test case bắt buộc theo đề: **14**.
- Số test case bắt buộc thành công: **14/14**.
- Số verifier module và integration bổ sung: **14/14**.
- Tổng số verifier thành công: **28/28**.
- Kết luận: **PASS - đáp ứng toàn bộ test case bắt buộc của Bài tập 3**.
- Lần xác minh gần nhất: **02/11/2026**.

## Test case bắt buộc

| ID | Thư mục | Nội dung | Kết quả mong đợi | Kết quả thực tế |
|---:|---|---|---|---|
| T01 | `T01_Rule_loader` | Rule hợp lệ, comment và dòng trống | Chỉ rule hợp lệ được chuyển sang parser | **PASS** |
| T02 | `T02_Invalid_rule` | Rule sai cú pháp | Đánh dấu invalid, có lý do và tiếp tục | **PASS** |
| T03 | `T03_Unsupported_keyword` | Keyword ngoài phạm vi | Đánh dấu unsupported, không crash | **PASS** |
| T04 | `T04_Rule_header` | TCP, IP/CIDR và port/range | Internal Rule Object đúng | **PASS** |
| T05 | `T05_Direction` | Direction `->` và `<>` | Match đúng một chiều và hai chiều | **PASS** |
| T06 | `T06_Indexer` | Candidate theo IP, TCP, UDP và any | Trả đúng tập candidate rule | **PASS** |
| T07 | `T07_Header_no_match` | Header không match | Loại rule trước content matching | **PASS** |
| T08 | `T08_Flow_state` | `flow:to_server,established` | Match đúng flow context | **PASS** |
| T09 | `T09_Content_nocase` | Content có và không có `nocase` | Phân biệt hoa thường đúng | **PASS** |
| T10 | `T10_Offset_depth` | Content có `offset/depth` | Chỉ match trong vùng chỉ định | **PASS** |
| T11 | `T11_Distance_within` | Hai content có `distance/within` | Relative matching đúng | **PASS** |
| T12 | `T12_Flags_dsize` | TCP flags và payload size | Match đúng flags và dsize | **PASS** |
| T13 | `T13_Multiple_matches` | Một event match nhiều rule | Sinh đầy đủ mọi kết quả match | **PASS** |
| T14 | `T14_Detection_event` | Detection Event | Đủ rule, flow, 5-tuple, protocol và match info | **PASS** |

## Verifier bổ sung

| Verifier | Phạm vi |
|---|---|
| `Rule_model` | Contract của Internal Rule Object |
| `Rule_loader` | Đọc và lọc file rule an toàn |
| `Rule_parser` | Tách header và quoted options |
| `Rule_validator` | Phân loại rule và kiểm tra giá trị |
| `Rule_repository` | Lập chỉ mục và chọn candidate rule |
| `Header_matcher` | Protocol, IP, port và direction |
| `Flow_matcher` | Direction và connection state |
| `Content_matcher` | Content, modifier và backtracking |
| `Packet_matcher` | TCP flags và dsize |
| `Matching_engine` | Kết hợp các matcher |
| `Evaluation_engine` | Nhiều match và thống kê đánh giá |
| `Detection_event` | Detection Event thống nhất |
| `Core_engine_pipeline` | Pipeline, field isolation và `matched_field` |
| `Flow_context_integration` | Tích hợp Flow Tracker của BT2 với Core Engine |

## Cách chạy lại test bắt buộc

Ví dụ với T14, chạy từ thư mục gốc project:

```bash
python TEST/BT3/T14_Detection_event/run_test.py
python TEST/BT3/T14_Detection_event/verify.py
```

Chạy lại toàn bộ runner và verifier:

```bash
find TEST/BT3 -path '*/T*/run_test.py' -print | sort | while read -r test_file; do
  python "$test_file" || exit 1
done

find TEST/BT3 -name verify.py -print | sort | while read -r test_file; do
  python "$test_file" || exit 1
done
```

Kịch bản thành công khi verifier in thông báo bắt đầu bằng `PASS` và kết thúc với exit code `0`.
