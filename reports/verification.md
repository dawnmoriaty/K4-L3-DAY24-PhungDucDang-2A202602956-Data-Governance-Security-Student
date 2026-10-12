# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
  - OS: Fedora Linux 43 (x86_64, Linux 6.13) / WSL
  - Python: 3.11.16 (`.venv/bin/python`)
  - Gitleaks: v8.30.1 (`gitleaks version 8.30.1`)
- `python -m pytest tests/ -q`:
  `33 passed in 0.71s` (Đạt 100% tất cả các bài kiểm tra: `test_pii.py`, `test_policy.py`, `test_obo.py`, `test_split.py`, `test_injection.py`, `test_ledger.py`, `test_supply_chain.py`).
- `pre-commit run --all-files`:
  `Detect hardcoded secrets.................................................Passed`
- Ledger verify:
  `verify(Path("reports/ledger.jsonl")) -> True` (Chuỗi băm mật mã SHA-256 gồm 46 bản ghi được xác thực liên tục, toàn vẹn và không bị can thiệp).
- Kích thước nhật ký tấn công (Attack Containment Proof):
  - Trước khi sửa (`reports/attack-before.log`): `1192 bytes` (4 bản ghi rò rỉ dữ liệu qua sink HTTP POST).
  - Sau khi sửa (`reports/attack-after.log`): `0 bytes` (Chặn thành công 100% hành vi rò rỉ dữ liệu).
- Các lỗi còn lại:
  Không còn lỗi kỹ thuật hoặc bài test thất bại nào (0 failures, 0 errors, 0 leaks).
