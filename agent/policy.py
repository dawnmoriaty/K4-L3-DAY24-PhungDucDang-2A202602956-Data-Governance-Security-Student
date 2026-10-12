"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict:
    if PRINCIPALS_FILE.exists():
        return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    return {}


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra chính sách bảo mật cho từng tool call (PEP)."""
    # 1. Kiểm tra phân loại dữ liệu (public, internal, restricted)
    if context.data_classification not in ("public", "internal", "restricted"):
        return False, f"Invalid data classification: {context.data_classification}"

    # 2. Rule tối thiểu: restricted + egress_enabled -> DENY
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Restricted data classification cannot have egress enabled (minimum deny rule)"

    # 3. Kiểm tra danh tính người dùng (principal)
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return False, f"Unknown or missing principal: {context.principal_id!r}"

    p_info = principals[context.principal_id]

    # 4. Kiểm tra thời hạn hiệu lực (expires_at)
    if context.expires_at:
        try:
            exp = datetime.fromisoformat(context.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if exp <= datetime.now(timezone.utc):
                return False, f"Token expired at {context.expires_at}"
        except ValueError:
            return False, f"Invalid expires_at format: {context.expires_at}"

    # 5. Kiểm tra mục đích yêu cầu (request_purpose)
    allowed_purposes = p_info.get("purposes", [])
    if context.request_purpose and context.request_purpose not in allowed_purposes:
        return False, f"Purpose {context.request_purpose!r} not allowed for principal {context.principal_id}"

    # 6. Kiểm tra quyền của tool theo OBO:
    # effective_tools = principal.allowed_tools ∩ agent_scopes (và ∩ parent_scopes nếu delegation_depth > 0)
    allowed_tools = set(p_info.get("allowed_tools", []))
    if context.agent_scopes:
        effective_tools = allowed_tools.intersection(context.agent_scopes)
    else:
        effective_tools = allowed_tools

    if context.delegation_depth > 0:
        effective_tools = effective_tools.intersection(context.parent_scopes)

    if context.requested_tool and context.requested_tool not in effective_tools:
        return False, f"Tool {context.requested_tool!r} not in effective tools: {sorted(effective_tools)}"

    tool_desc = context.requested_tool or "access"
    return True, f"Action allowed: {tool_desc} by {context.principal_id} for purpose {context.request_purpose}"
