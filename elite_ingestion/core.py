"""Bounded local ingestion primitives; no network access or execution of content."""
from __future__ import annotations

import csv
import hashlib
import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_CSV_FIELDS = 256
SUSPICIOUS_MARKERS = (
    "ignore previous instructions", "reveal system prompt",
    "disregard all rules", "exfiltrate", "developer message:",
)


class DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class RecordRepresentationDigest:
    """Digest/size for an oversized raw record retained without retaining its bytes."""
    sha256: str
    size_bytes: int


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


def inspect_record(record: dict, source_id: str, operator_asserts_authorized: bool) -> tuple[str, list[str]]:
    reasons = []
    # This is only an operator-supplied assertion. It is not identity, legal,
    # contractual, or policy authorization enforcement.
    if not operator_asserts_authorized:
        reasons.append("source_not_authorized")
    if not isinstance(record, dict):
        reasons.append("record_not_object")
        return "quarantine", reasons
    if not isinstance(source_id, str) or not source_id.strip():
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


def _bounded_binary_lines(path: Path) -> Iterator[bytes | RecordRepresentationDigest]:
    """Yield lines without reading the entire file; enforce aggregate bytes."""
    total = 0
    with path.open("rb") as handle:
        while True:
            line = handle.readline(MAX_RECORD_BYTES + 1)
            if not line:
                break
            total += len(line)
            if total > MAX_FILE_BYTES:
                raise ValueError(f"input exceeds {MAX_FILE_BYTES} bytes")
            if len(line) > MAX_RECORD_BYTES:
                digest = hashlib.sha256()
                digest.update(line)
                record_size = len(line)
                while not line.endswith(b"\n"):
                    chunk = handle.readline(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    record_size += len(chunk)
                    digest.update(chunk)
                    if total > MAX_FILE_BYTES:
                        raise ValueError(f"input exceeds {MAX_FILE_BYTES} bytes")
                    if chunk.endswith(b"\n"):
                        break
                yield RecordRepresentationDigest(digest.hexdigest(), record_size)
            else:
                yield line


def _bounded_text_lines(path: Path) -> Iterator[str]:
    """UTF-8 text line iterator for csv.reader, with aggregate byte accounting."""
    total = 0
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        while True:
            line = handle.readline(MAX_RECORD_BYTES + 1)
            if not line:
                break
            encoded_size = len(line.encode("utf-8"))
            total += encoded_size
            if total > MAX_FILE_BYTES:
                raise ValueError(f"input exceeds {MAX_FILE_BYTES} bytes")
            if encoded_size > MAX_RECORD_BYTES:
                raise ValueError("CSV physical line exceeds record byte limit")
            yield line


def iter_records(path: Path, fmt: str) -> Iterator[tuple[int, dict, bytes | RecordRepresentationDigest]]:
    """Stream parsed records. Limits are enforced while reading, not after allocation."""
    if fmt == "jsonl":
        for line_no, line in enumerate(_bounded_binary_lines(path), 1):
            if isinstance(line, RecordRepresentationDigest):
                yield line_no, {"_record_too_large": True}, line
                continue
            if not line.strip():
                continue
            try:
                value = strict_json_loads(line.decode("utf-8"))
                yield line_no, value, line
            except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError):
                yield line_no, {"_parse_error": True}, line
    elif fmt == "csv":
        # Respect the csv module's configured field cap rather than mutating
        # its process-global setting. The aggregate input bound remains the
        # outer memory ceiling if an embedding application changes that cap.
        reader = csv.reader(_bounded_text_lines(path), strict=True)
        try:
            headers = next(reader)
        except StopIteration:
            raise ValueError("CSV input is empty") from None
        except csv.Error as exc:
            raise ValueError(f"malformed CSV header: {exc}") from exc
        if not headers or "content" not in headers:
            raise ValueError("CSV must contain a content column")
        if len(headers) > MAX_CSV_FIELDS or len(set(headers)) != len(headers):
            raise ValueError("CSV headers exceed field limit or contain duplicates")
        if any(not header for header in headers):
            raise ValueError("CSV headers must be non-empty")
        try:
            for row in reader:
                line_no = reader.line_num
                encoded = json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                if len(row) != len(headers):
                    yield line_no, {"_parse_error": True}, encoded[:MAX_RECORD_BYTES]
                elif len(encoded) > MAX_RECORD_BYTES or any(len(value.encode("utf-8")) > MAX_RECORD_BYTES for value in row):
                    yield line_no, {"_record_too_large": True}, RecordRepresentationDigest(
                        hashlib.sha256(encoded).hexdigest(), len(encoded)
                    )
                else:
                    yield line_no, dict(zip(headers, row)), encoded
        except csv.Error as exc:
            raise ValueError(f"malformed CSV or field exceeds the Python CSV parser limit: {exc}") from exc
    else:
        raise ValueError("format must be jsonl or csv")


def iter_ingest(
    path: Path,
    fmt: str,
    source_id: str,
    operator_asserts_authorized: bool = False,
    *,
    import_id: str | None = None,
) -> Iterator[tuple[str, dict]]:
    """Yield (destination, envelope) one record at a time for bounded-memory callers."""
    run_id = import_id or str(uuid.uuid4())
    for line_no, record, raw in iter_records(path, fmt):
        if not isinstance(record, dict) or record.get("_parse_error"):
            status, reasons = "quarantine", ["parse_error_or_duplicate_key"]
        elif record.get("_record_too_large"):
            status, reasons = "quarantine", ["record_too_large"]
        else:
            status, reasons = inspect_record(record, source_id, operator_asserts_authorized)
        envelope = {
            "record_id": f"{run_id}:{line_no}",
            "import_id": run_id,
            "source_id": source_id,
            "source_format": fmt,
            "source_record": line_no,
            "record_representation_sha256": raw.sha256 if isinstance(raw, RecordRepresentationDigest) else sha256_bytes(raw),
            "record_representation_size_bytes": raw.size_bytes if isinstance(raw, RecordRepresentationDigest) else len(raw),
            "record_representation_scope": (
                "jsonl.raw_line.bytes" if fmt == "jsonl"
                else "csv.parsed_row.canonical_json.utf8"
            ),
            "record": record,
            "decision": status,
            "reasons": reasons,
        }
        yield status, envelope


def ingest(
    path: Path,
    fmt: str,
    source_id: str,
    authorized: bool = False,
    *,
    import_id: str | None = None,
) -> tuple[list[dict], list[dict]]:
    """Compatibility wrapper; prefer iter_ingest for bounded-memory processing."""
    accepted, quarantine = [], []
    for status, envelope in iter_ingest(
        path, fmt, source_id, authorized, import_id=import_id
    ):
        (accepted if status == "accepted" else quarantine).append(envelope)
    return accepted, quarantine


# Backwards-compatible public name. Unlike the former implementation this
# iterator does not materialize the input file.
load_records = iter_records
