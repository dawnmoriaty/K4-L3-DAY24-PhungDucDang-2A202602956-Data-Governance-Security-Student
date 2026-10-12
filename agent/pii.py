"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).
"""
from __future__ import annotations

import re

# Regex patterns cho 4 loại PII
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_RE = re.compile(
    r"(?i:\b(?:STK|số tài khoản|so tai khoan|tài khoản ngân hàng|tai khoan ngan hang|tài khoản|tai khoan)\s*[:.]?\s*)([0-9]{8,16})\b"
)
CCCD_RE = re.compile(r"\b[0-9]{12}\b")
PHONE_RE = re.compile(r"(?:\b0|\+84)[0-9]{9}\b")


def detect(text: str) -> list[dict]:
    """Phát hiện 4 loại PII: VN_CCCD, VN_PHONE, VN_BANK_ACCOUNT, EMAIL."""
    entities: list[dict] = []
    occupied: set[int] = set()

    # 1. EMAIL
    for m in EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
        occupied.update(range(m.start(), m.end()))

    # 2. VN_BANK_ACCOUNT (dựa vào từ khoá STK / số tài khoản đứng trước)
    for m in BANK_RE.finditer(text):
        start, end = m.start(1), m.end(1)
        if not any(idx in occupied for idx in range(start, end)):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})
            occupied.update(range(start, end))

    # 3. VN_CCCD (12 chữ số liên tiếp, không trùng vùng STK)
    for m in CCCD_RE.finditer(text):
        start, end = m.start(), m.end()
        if not any(idx in occupied for idx in range(start, end)):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})
            occupied.update(range(start, end))

    # 4. VN_PHONE (10 chữ số bắt đầu bằng 0, không trùng vùng CCCD / STK)
    for m in PHONE_RE.finditer(text):
        start, end = m.start(), m.end()
        if not any(idx in occupied for idx in range(start, end)):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})
            occupied.update(range(start, end))

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các thực thể PII bằng [REDACTED_<TYPE>] theo thứ tự từ cuối về đầu."""
    entities = detect(text)
    # Thay thế từ cuối chuỗi về đầu để không làm xê dịch offset ký tự
    for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
        replacement = f"[REDACTED_{ent['type']}]"
        text = text[: ent["start"]] + replacement + text[ent["end"] :]
    return text
