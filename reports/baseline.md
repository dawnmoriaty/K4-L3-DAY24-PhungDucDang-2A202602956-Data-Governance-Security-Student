# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Hàm `_naive_loop(message, llm)` tại `agent/loop.py:27` chỉ nhận chuỗi câu hỏi và đối tượng LLM, hoàn toàn không có `agent_id`, `run_id` hay thông tin định danh người dùng. Mặc dù cờ `--as` được parse trong `main()` tại `agent/loop.py:83-85`, nhưng khi chưa có runner, luồng fallback tại `agent/loop.py:74` gọi trực tiếp `_naive_loop(message, llm)` và bỏ qua `principal_id`.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có policy hay cơ chế kiểm soát quyền (PEP) nào kiểm tra mục đích, quyền hay loại dữ liệu. Kẻ tấn công thực sự quyết định việc đọc hồ sơ và phát tán dữ liệu thông qua chỉ thị injection được `llm.find_injection()` trích xuất tại `agent/loop.py:34-44`. Về phía `agent/tools.py:68-85`, hàm `http_post()` chỉ kiểm tra whitelist `127.0.0.1:10024` để cô lập thử nghiệm chứ không hề kiểm tra dữ liệu nào được phép gửi đi.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Dòng tạo body POST chứa hồ sơ khách hàng là `agent/loop.py:44`: `tools.http_post(injected.target_url, {"records": collected})` với `collected` chứa dữ liệu đọc từ `tools.read_customer()`. Việc sink đã nhận body đó được ghi lại trong file `reports/sink.log` bởi hàm `Handler.do_POST()` tại `sink/sink.py:40-47`.
