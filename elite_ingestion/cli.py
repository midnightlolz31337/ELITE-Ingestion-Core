"""CLI for streaming local JSONL/CSV ingestion."""
import argparse
import json
import os
import tempfile
from pathlib import Path

from .core import iter_ingest


def write_jsonl_stream(path: Path, records) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for item in records:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="elite-ingest")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("ingest")
    command.add_argument("input", type=Path)
    command.add_argument("--source-id", required=True)
    command.add_argument("--format", choices=("jsonl", "csv"))
    command.add_argument(
        "--operator-asserts-authorized", "--authorized",
        dest="operator_asserts_authorized", action="store_true",
        help="operator assertion only; not a legal, contractual, or policy authorization system",
    )
    command.add_argument("--output-dir", type=Path, default=Path("output"))
    inspect = sub.add_parser("inspect")
    inspect.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    if args.command == "inspect":
        for file in args.files:
            count = sum(1 for line in file.open(encoding="utf-8") if line.strip()) if file.exists() else 0
            print(f"{file}: {count} records")
        return 0

    fmt = args.format or args.input.suffix.lstrip(".").lower()
    if fmt not in {"jsonl", "csv"}:
        parser.error("specify --format jsonl or csv")

    accepted_path = args.output_dir / "accepted.jsonl"
    quarantine_path = args.output_dir / "quarantine.jsonl"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    accepted_count = quarantine_count = 0

    # Stage both outputs in the destination filesystem. A failed or interrupted
    # import leaves previously completed output files untouched.
    try:
        with tempfile.TemporaryDirectory(prefix=".elite-ingest-", dir=args.output_dir) as staging:
            staged_accepted = Path(staging) / "accepted.jsonl"
            staged_quarantine = Path(staging) / "quarantine.jsonl"
            with staged_accepted.open("w", encoding="utf-8") as accepted, staged_quarantine.open("w", encoding="utf-8") as quarantine:
                for status, envelope in iter_ingest(
                    args.input, fmt, args.source_id, args.operator_asserts_authorized
                ):
                    target = accepted if status == "accepted" else quarantine
                    target.write(json.dumps(envelope, ensure_ascii=False, sort_keys=True) + "\n")
                    if status == "accepted":
                        accepted_count += 1
                    else:
                        quarantine_count += 1
            os.replace(staged_accepted, accepted_path)
            os.replace(staged_quarantine, quarantine_path)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"elite-ingest: import failed; existing outputs were preserved where possible: {exc}\n")

    print(f"accepted={accepted_count} quarantined={quarantine_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
