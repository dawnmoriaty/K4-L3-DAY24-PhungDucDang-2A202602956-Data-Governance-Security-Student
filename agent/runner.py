"""BƯỚC 3c & 3d — trifecta split + egress allowlist + audit ledger.

Tách 1 yêu cầu người dùng thành 2 run riêng biệt:
    Run A: gọi search_docs (untrusted content). Không gọi read_customer, không gọi http_post.
           Trích xuất ticket_id (int) từ tên file (vd "ticket-007.md" -> 7).
           Che PII trong nội dung trước khi tóm tắt.
    Run B: map ticket_id -> customer_id từ trường related_tickets trong data/customers.json.
           Kiểm tra quyền qua policy.check() trước khi gọi read_customer.
           Nếu có chỉ thị injection yêu cầu egress (http_post), kiểm tra policy và ghi deny vào ledger.
Mọi tool call đều qua policy.check() và ghi vào audit ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _hash_args(args) -> str:
    s = json.dumps(args, sort_keys=True, ensure_ascii=False) if isinstance(args, (dict, list)) else str(args)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    """Xử lý yêu cầu người dùng theo kiến trúc Trifecta Split & OBO."""
    ledger_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    now_ts = datetime.now(timezone.utc).isoformat()

    # --- RUN A: search_docs (Untrusted Content) ---
    ctx_a = policy.PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="lab24-agent/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=("search_docs",),
        expires_at=expires_at,
    )
    allow_a, reason_a = policy.check(ctx_a)
    ledger.append({
        "ts": now_ts,
        "agent_id": "lab24-agent/run-a",
        "run_id": "run-a",
        "on_behalf_of": principal_id,
        "tool": "search_docs",
        "args_hash": _hash_args(message),
        "classification": "internal",
        "decision": "allow" if allow_a else "deny",
        "reason": reason_a,
        "expires_at": expires_at,
    }, ledger_path)

    if not allow_a:
        return "Bị từ chối quyền tìm kiếm tài liệu."

    docs = tools.search_docs(message)

    # 1. Trích xuất ticket_id (dạng số int) từ tên file .md (ví dụ: ticket-001.md -> 1)
    ticket_ids: set[int] = set()
    for doc in docs:
        match = re.search(r"ticket-(\d+)", doc.get("id", ""))
        if match:
            ticket_ids.add(int(match.group(1)))

    # 2. Che PII trong nội dung trước khi đưa vào bản tóm tắt
    sanitized_docs = [
        {"id": d["id"], "text": pii.redact(d["text"])}
        for d in docs
    ]

    # --- RUN B: read_customer dựa trên nguồn tin cậy related_tickets ---
    customers = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))
    matched_customers = [
        c for c in customers
        if any(tid in c.get("related_tickets", []) for tid in ticket_ids)
    ]

    for customer in matched_customers:
        cid = customer["customer_id"]
        ctx_b = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=("search_docs", "read_customer"),
            expires_at=expires_at,
        )
        allow_b, reason_b = policy.check(ctx_b)
        ledger.append({
            "ts": now_ts,
            "agent_id": "lab24-agent/run-b",
            "run_id": "run-b",
            "on_behalf_of": principal_id,
            "tool": "read_customer",
            "args_hash": _hash_args(cid),
            "classification": "restricted",
            "decision": "allow" if allow_b else "deny",
            "reason": reason_b,
            "expires_at": expires_at,
        }, ledger_path)

        if allow_b:
            tools.read_customer(cid)

    # 3. Nếu lure yêu cầu gửi dữ liệu (egress), kiểm tra policy http_post riêng
    combined_raw_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_raw_text)
    if injected is not None and injected.target_url:
        ctx_post = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="lab24-agent/run-b",
            delegation_depth=0,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=("search_docs", "read_customer", "http_post"),
            expires_at=expires_at,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append({
            "ts": now_ts,
            "agent_id": "lab24-agent/run-b",
            "run_id": "run-b",
            "on_behalf_of": principal_id,
            "tool": "http_post",
            "args_hash": _hash_args(injected.target_url),
            "classification": "restricted",
            "decision": "allow" if allow_post else "deny",
            "reason": reason_post,
            "expires_at": expires_at,
        }, ledger_path)

        if allow_post:
            tools.http_post(injected.target_url, {"records": []})

    return llm.summarize(sanitized_docs)
