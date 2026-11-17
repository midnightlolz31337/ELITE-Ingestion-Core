import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import elite_ingestion.core as core
from elite_ingestion.cli import main


class CsvFailureTests(unittest.TestCase):
    def test_oversized_multiline_field_is_a_controlled_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.csv"
            path.write_text('content\n"' + ("x" * 20) + '\n' + ("y" * 20) + '"\n', encoding="utf-8")
            previous = core.csv.field_size_limit()
            core.csv.field_size_limit(32)
            try:
                with self.assertRaisesRegex(ValueError, "Python CSV parser limit"):
                    list(core.iter_records(path, "csv"))
            finally:
                core.csv.field_size_limit(previous)
            self.assertEqual(core.csv.field_size_limit(), previous)

    def test_malformed_csv_is_a_controlled_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.csv"
            path.write_text('content\n"unterminated\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed CSV"):
                list(core.iter_records(path, "csv"))

    def test_field_limit_is_restored_when_generator_is_closed_early(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.csv"
            path.write_text("content\none\ntwo\n", encoding="utf-8")
            previous = core.csv.field_size_limit()
            with patch.object(core, "MAX_RECORD_BYTES", 64):
                records = core.iter_records(path, "csv")
                next(records)
                records.close()
            self.assertEqual(core.csv.field_size_limit(), previous)

    def test_failed_import_preserves_previous_output_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.jsonl"
            source.write_text('{"content":"this record exceeds the test limit"}\n', encoding="utf-8")
            output = root / "output"
            output.mkdir()
            accepted = output / "accepted.jsonl"
            quarantine = output / "quarantine.jsonl"
            accepted.write_text("previous accepted\n", encoding="utf-8")
            quarantine.write_text("previous quarantine\n", encoding="utf-8")
            with patch.object(core, "MAX_FILE_BYTES", 8):
                with self.assertRaises(SystemExit) as raised:
                    main([
                        "ingest", str(source), "--source-id", "test",
                        "--operator-asserts-authorized", "--output-dir", str(output),
                    ])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(accepted.read_text(encoding="utf-8"), "previous accepted\n")
            self.assertEqual(quarantine.read_text(encoding="utf-8"), "previous quarantine\n")
            self.assertEqual(sorted(item.name for item in output.iterdir()), [
                "accepted.jsonl", "quarantine.jsonl"
            ])


if __name__ == "__main__":
    unittest.main()
