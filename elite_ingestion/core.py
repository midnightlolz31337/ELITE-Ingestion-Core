"""Bounded local ingestion primitives; no network access or execution of content."""
from __future__ import annotations
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
SUSPICIOUS_MARKERS = (
    "ignore previous instructions", "reveal system prompt",
    "disregard all rules", "exfiltrate", "developer message:",
)

class DuplicateKeyError(ValueError):
    pass

def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

def strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_unique_object)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def inspect_record(record: dict, source_id: str, source_authorized: bool) -> tuple[str, list[str]]:
    reasons = []
    if not source_authorized:
        reasons.append("source_not_authorized")
    if not isinstance(record, dict):
        reasons.append("record_not_object")
        return "quarantine", reasons
    if not source_id.strip():
        reasons.append("missing_source_id")
    if "content" not in record:
        reasons.append("missing_content")
    content = record.get("content")
    if isinstance(content, str):
        text = content
    elif isinstance(content, dict) and isinstance(content.get("text"), str):
        text = content["text"]
    else:
        text = None
        reasons.append("content_not_string_or_text_object")
    if text is not None:
        folded = text.casefold()
        if any(marker in folded for marker in SUSPICIOUS_MARKERS):
            reasons.append("instruction_injection_indicator")
    return ("quarantine" if reasons else "accepted"), reasons

def load_records(path: Path, fmt: str) -> Iterable[tuple[int, dict, bytes]]:
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"input exceeds {MAX_FILE_BYTES} bytes")
    if fmt == "jsonl":
        for line_no, line in enumerate(raw.splitlines(), 1):
            if not line.strip():
                continue
            if len(line) > MAX_RECORD_BYTES:
                yield line_no, {"content": None}, line
                continue
            try:
                value = strict_json_loads(line.decode("utf-8"))
                yield line_no, value, line
            except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError):
                yield line_no, {"_parse_error": True}, line
    elif fmt == "csv":
        text = raw.decode("utf-8-sig")
        rows = csv.DictReader(text.splitlines())
        if not rows.fieldnames or "content" not in rows.fieldnames:
            raise ValueError("CSV must contain a content column")
        for line_no, row in enumerate(rows, 2):
            encoded = json.dumps(row, ensure_ascii=False, sort_keys=True).encode()
            if len(encoded) > MAX_RECORD_BYTES:
                yield line_no, {"_record_too_large": True}, encoded
            else:
                yield line_no, row, encoded
    else:
        raise ValueError("format must be jsonl or csv")

def ingest(path: Path, fmt: str, source_id: str, authorized: bool) -> tuple[list[dict], list[dict]]:
    accepted, quarantine = [], []
    for line_no, record, raw in load_records(path, fmt):
        if not isinstance(record, dict) or record.get("_parse_error"):
            status, reasons = "quarantine", ["parse_error_or_duplicate_key"]
        elif record.get("_record_too_large"):
            status, reasons = "quarantine", ["record_too_large"]
        else:
            status, reasons = inspect_record(record, source_id, authorized)
        envelope = {
            "record_id": f"{source_id}:{line_no}",
            "source_id": source_id,
            "source_record": line_no,
            "content_sha256": sha256_bytes(raw),
            "record": record,
            "decision": status,
            "reasons": reasons,
        }
        (accepted if status == "accepted" else quarantine).append(envelope)
    return accepted, quarantine
