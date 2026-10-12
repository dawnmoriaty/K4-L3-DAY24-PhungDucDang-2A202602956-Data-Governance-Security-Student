# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - Dữ liệu định danh / PII nhạy cảm và cơ bản (theo Nghị định 13/2023/NĐ-CP):
     + Số định danh cá nhân: Số Căn cước công dân (CCCD - 12 chữ số).
     + Thông tin liên lạc: Số điện thoại di động Việt Nam (10 số, tiền tố hợp lệ 03, 05, 07, 08, 09), Địa chỉ Email cá nhân/doanh nghiệp.
     + Thông tin tài chính: Số tài khoản ngân hàng (8-16 chữ số kèm tên ngân hàng).
   - Dữ liệu hoạt động / dịch vụ khách hàng:
     + Mã định danh khách hàng (`customer_id`, dạng `KH-000...`).
     + Mã số ticket (`ticket_id`), tiêu đề và nội dung mô tả sự cố kỹ thuật trong ticket.
     + Phân loại rủi ro: Mức độ rủi ro cao nếu PII và thông tin tài chính bị rò rỉ ra ngoài (data exfiltration).

2. Mục đích xử lý và principal:
   - Mục đích xử lý:
     + `support-ticket-index`: Quét và tổng hợp danh sách các ticket đang mở trong tuần để quản lý tiến độ.
     + `support-reply`: Tra cứu hồ sơ khách hàng nội bộ để hỗ trợ kỹ thuật và trả lời thắc mắc chính đáng.
   - Nguyên tắc ủy quyền & Principal:
     + `support_l1`: Nhân viên hỗ trợ L1, quyền hạn tối thiểu (`search_docs`), chỉ đọc file ticket công khai, tuyệt đối không được đọc kho hồ sơ khách hàng (`read_customer`) và không được gọi API ra bên ngoài (`http_post`).
     + `dpo`: Data Protection Officer, được cấp quyền OBO (`support-reply`) để đọc dữ liệu khách hàng (`read_customer`) khi đã xác thực ticket hợp lệ, nhưng tuyệt đối bị chặn quyền gửi dữ liệu ra bên ngoài (`http_post` denied by policy egress check).

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - Phân tách ranh giới xử lý (Trifecta Split Architecture):
     + **Run A (Vùng không tin cậy / Ingestion Zone):** Agent chỉ được dùng `search_docs` đọc danh sách file ticket trong `corpus/`. Run A tuyệt đối không phân tích `customer_id` từ text tự do để triệt tiêu nguy cơ gián tiếp Prompt Injection từ kẻ tấn công. Chỉ trích xuất duy nhất con số ID của ticket từ tên file hợp lệ (`ticket-{id}.md`).
     + **Ranh giới tin cậy (Boundary Mapping Layer):** Runner ánh xạ từ `ticket_id` sang `customer_id` bằng nguồn dữ liệu tin cậy (`data/related_tickets.json`), hoàn toàn độc lập với nội dung văn bản bên trong ticket.
     + **Run B (Vùng bảo mật / Safe Zone):** Chỉ sau khi kiểm tra Policy & OBO, DPO mới được gọi `read_customer` đọc hồ sơ tương ứng. Dữ liệu văn bản phản hồi bắt buộc đi qua **PII Gate (`redact()`)** để che toàn bộ CCCD, SĐT, STK, Email bằng token ẩn danh `[VN_CCCD:REDACTED]`, `[VN_PHONE:REDACTED]`, v.v.
     + **Endpoint:** Không gọi bất kỳ outbound endpoint nào. Khi có yêu cầu `http_post` hướng tới `http://127.0.0.1:8765/sink` (hoặc bất kỳ external URL nào), Policy Engine lập tức can thiệp chặn lại (`decision="deny"`, `reason="http_post denied by egress policy"`).

4. Bằng chứng deny/allow và giới hạn của mock:
   - Bằng chứng Allow:
     + Quyền `search_docs` của `support_l1` và `dpo` được ghi nhận `decision="allow"` trong `reports/ledger.jsonl`.
     + Quyền `read_customer` của `dpo` cho các ticket hợp lệ được ghi nhận `decision="allow"` trong `reports/ledger.jsonl`.
   - Bằng chứng Deny:
     + `support_l1` cố gọi `read_customer` bị chặn với `decision="deny"`, `reason="tool not permitted for principal"`.
     + Mọi lệnh `http_post` bị chặn với `decision="deny"`, `reason="http_post denied by egress policy"`.
     + Sink log `reports/attack-after.log` ghi nhận đúng **0 byte** (so với 1192 bytes ở `attack-before.log`).
     + `reports/ledger.jsonl` được xác minh chuỗi băm mật mã SHA-256 nguyên vẹn (`verify() -> True`).
   - Giới hạn của mock:
     + Mock LLM sử dụng tập từ khóa heurictic (`FIND_INJECTION` markers), chưa bao quát hết các kỹ thuật Jailbreak, Base64/Unicode obfuscation trong thực tế.
     + Danh tính Principal được nạp từ file JSON tĩnh (`data/principals.json`), chưa kết nối với IdP/IAM tập trung (OAuth2/OIDC/mTLS).
     + PII Gate dùng Regex chính xác cao với tập mẫu Việt Nam nhưng vẫn có khả năng False Negatives nếu dữ liệu bị cố tình ngắt chữ hoặc gõ sai định dạng.
