# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks phiên bản 8.30.1 (`gitleaks version 8.30.1`).
- Commit chứa token giả: `1bdd849` (commit `1bdd8490fa9d2b2700305612f0e014e7a77d13aa` thêm file `lab-fake-secret.txt`).
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`
  - Rule: `lab24-synthetic-token`
  - Kết quả: Lệnh `gitleaks git --config .gitleaks.toml --redact -v .` phát hiện 1 leak ở commit `1bdd849` (token mẫu `lab24-sec-synthetic-token-for-audit-do-not-use-in-prod`), trả về mã thoát 1 (kết quả mong đợi khi phát hiện rò rỉ trong lịch sử).
- Kết quả quét file hiện tại: Lệnh `gitleaks dir --config .gitleaks.toml --redact -v .` trả về 0 leaks (exit code 0), thư mục làm việc hiện tại và HEAD không chứa secret.
- Nếu đây là credential thật, cần xử lý thế nào:
  - Áp dụng nguyên tắc xem như credential đã bị xâm phạm (assumed breached): ngay lập tức thu hồi (revoke) và xoay vòng (rotate) credential trên hệ thống dịch vụ tương ứng.
  - Kiểm tra audit logs và access logs của hệ thống kể từ mốc thời gian commit `1bdd849` xuất hiện để phát hiện các truy cập bất thường hoặc hành vi đánh cắp dữ liệu.
  - Sử dụng công cụ làm sạch lịch sử git (`git-filter-repo` hoặc BFG Repo-Cleaner) để xóa bỏ hoàn toàn commit/blob chứa secret khỏi toàn bộ Git history, đồng thời yêu cầu tất cả cộng tác viên pull/re-clone repo mới.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi HEAD chỉ làm file không còn xuất hiện trong cây thư mục làm việc hiện tại, nhưng Git vẫn lưu trữ trọn vẹn đối tượng blob và commit `1bdd849` trong lịch sử. Bất kỳ ai clone hoặc có quyền đọc repo đều có thể khôi phục lại secret bằng `git show 1bdd849:lab-fake-secret.txt`. Do đó, nếu credential không được rotate/thu hồi, nó vẫn có thể bị kẻ tấn công khai thác.
  - Pin dependency (bằng `requirements.lock` kèm sha256 hashes) chỉ giải quyết bài toán toàn vẹn chuỗi cung ứng gói bên ngoài (tránh supply-chain attacks như compromised package hay dependency confusion), hoàn toàn không thể bảo vệ hoặc ngăn chặn việc rò rỉ secret nội bộ trong mã nguồn dự án.
