"""CLI for local, bounded JSONL/CSV ingestion."""
import argparse
import json
from pathlib import Path
from .core import ingest

def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for item in records:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")

def main() -> int:
    parser = argparse.ArgumentParser(prog="elite-ingest")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("ingest")
    command.add_argument("input", type=Path)
    command.add_argument("--source-id", required=True)
    command.add_argument("--format", choices=("jsonl", "csv"))
    command.add_argument("--authorized", action="store_true", help="operator assertion for this local run")
    command.add_argument("--output-dir", type=Path, default=Path("output"))
    inspect = sub.add_parser("inspect")
    inspect.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    if args.command == "inspect":
        for file in args.files:
            count = sum(1 for line in file.open(encoding="utf-8") if line.strip()) if file.exists() else 0
            print(f"{file}: {count} records")
        return 0
    fmt = args.format or args.input.suffix.lstrip(".").lower()
    if fmt not in {"jsonl", "csv"}:
        parser.error("specify --format jsonl or csv")
    accepted, quarantine = ingest(args.input, fmt, args.source_id, args.authorized)
    write_jsonl(args.output_dir / "accepted.jsonl", accepted)
    write_jsonl(args.output_dir / "quarantine.jsonl", quarantine)
    print(f"accepted={len(accepted)} quarantined={len(quarantine)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
