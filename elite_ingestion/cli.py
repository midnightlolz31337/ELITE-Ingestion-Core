"""CLI for streaming local JSONL/CSV ingestion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .core import iter_ingest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_current_pointer(output_dir: Path, manifest: dict) -> None:
    pointer = output_dir / "CURRENT.json"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_dir,
            prefix=".CURRENT.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(manifest, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, pointer)
        temporary = None
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _read_current_pointer(pointer: Path) -> tuple[dict, Path]:
    try:
        manifest = json.loads(pointer.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read current generation manifest: {exc}") from exc

    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "generation_id", "generation_path", "created_at",
        "accepted_count", "quarantine_count", "files",
    }:
        raise ValueError("CURRENT.json has an invalid structure")
    if manifest["schema_version"] != "1":
        raise ValueError("unsupported CURRENT.json schema version")

    generation_id = manifest["generation_id"]
    if not isinstance(generation_id, str) or not generation_id:
        raise ValueError("CURRENT.json generation_id is invalid")
    expected_generation_path = f"generations/{generation_id}"
    if manifest["generation_path"] != expected_generation_path:
        raise ValueError("CURRENT.json generation path is invalid")

    output_dir = pointer.parent.resolve()
    generations_dir = (output_dir / "generations").resolve()
    generation_dir = (output_dir / expected_generation_path).resolve()
    if generation_dir.parent != generations_dir or not generation_dir.is_dir() or generation_dir.is_symlink():
        raise ValueError("current generation directory is missing or outside generations/")

    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != {"accepted.jsonl", "quarantine.jsonl"}:
        raise ValueError("CURRENT.json file map is invalid")
    for name in ("accepted.jsonl", "quarantine.jsonl"):
        entry = files[name]
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "sha256"}:
            raise ValueError(f"CURRENT.json entry for {name} is invalid")
        expected_path = f"{expected_generation_path}/{name}"
        if entry["path"] != expected_path:
            raise ValueError(f"CURRENT.json path for {name} is invalid")
        file_path = generation_dir / name
        if file_path.is_symlink() or not file_path.is_file():
            raise ValueError(f"current generation file is missing or unsafe: {name}")
        if isinstance(entry["size"], bool) or not isinstance(entry["size"], int):
            raise ValueError(f"CURRENT.json size for {name} is invalid")
        if file_path.stat().st_size != entry["size"] or _sha256_file(file_path) != entry["sha256"]:
            raise ValueError(f"current generation integrity check failed: {name}")

    return manifest, generation_dir


def _commit_generation(
    output_dir: Path,
    staging_dir: Path,
    generation_id: str,
    accepted_count: int,
    quarantine_count: int,
) -> Path:
    generations_dir = output_dir / "generations"
    if generations_dir.is_symlink():
        raise ValueError("generations/ must not be a symlink")
    generations_dir.mkdir(parents=True, exist_ok=True)
    generation_dir = generations_dir / generation_id
    if generation_dir.exists():
        raise ValueError("generation ID already exists")

    os.replace(staging_dir, generation_dir)
    files = {}
    for name in ("accepted.jsonl", "quarantine.jsonl"):
        file_path = generation_dir / name
        files[name] = {
            "path": f"generations/{generation_id}/{name}",
            "size": file_path.stat().st_size,
            "sha256": _sha256_file(file_path),
        }

    manifest = {
        "schema_version": "1",
        "generation_id": generation_id,
        "generation_path": f"generations/{generation_id}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "accepted_count": accepted_count,
        "quarantine_count": quarantine_count,
        "files": files,
    }
    try:
        _write_current_pointer(output_dir, manifest)
    except Exception:
        shutil.rmtree(generation_dir, ignore_errors=True)
        raise
    return generation_dir


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
            if file.name == "CURRENT.json":
                manifest, generation_dir = _read_current_pointer(file)
                print(f"generation={manifest['generation_id']}")
                print(f"accepted={manifest['accepted_count']} path={generation_dir / 'accepted.jsonl'}")
                print(f"quarantined={manifest['quarantine_count']} path={generation_dir / 'quarantine.jsonl'}")
            else:
                count = sum(1 for line in file.open(encoding="utf-8") if line.strip()) if file.exists() else 0
                print(f"{file}: {count} records")
        return 0

    fmt = args.format or args.input.suffix.lstrip(".").lower()
    if fmt not in {"jsonl", "csv"}:
        parser.error("specify --format jsonl or csv")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    if args.output_dir.is_symlink():
        parser.exit(2, "elite-ingest: output directory must not be a symlink\n")

    generation_id = str(uuid.uuid4())
    staging_dir: Path | None = None
    generation_dir: Path | None = None
    accepted_count = quarantine_count = 0

    try:
        staging_dir = Path(tempfile.mkdtemp(prefix=".elite-ingest-", dir=args.output_dir))
        staged_accepted = staging_dir / "accepted.jsonl"
        staged_quarantine = staging_dir / "quarantine.jsonl"
        with staged_accepted.open("w", encoding="utf-8") as accepted, staged_quarantine.open("w", encoding="utf-8") as quarantine:
            for status, envelope in iter_ingest(
                args.input,
                fmt,
                args.source_id,
                args.operator_asserts_authorized,
                import_id=generation_id,
            ):
                target = accepted if status == "accepted" else quarantine
                target.write(json.dumps(envelope, ensure_ascii=False, sort_keys=True) + "\n")
                if status == "accepted":
                    accepted_count += 1
                else:
                    quarantine_count += 1
            accepted.flush()
            os.fsync(accepted.fileno())
            quarantine.flush()
            os.fsync(quarantine.fileno())

        generation_dir = _commit_generation(
            args.output_dir,
            staging_dir,
            generation_id,
            accepted_count,
            quarantine_count,
        )
        staging_dir = None
    except (OSError, ValueError) as exc:
        if staging_dir is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)
        parser.exit(2, f"elite-ingest: import failed; previous CURRENT generation was preserved: {exc}\n")

    print(f"generation={generation_id}")
    print(f"accepted={accepted_count} quarantined={quarantine_count}")
    print(f"current={args.output_dir / 'CURRENT.json'}")
    print(f"generation_dir={generation_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
