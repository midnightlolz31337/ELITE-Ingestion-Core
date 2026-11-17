# ELITE Ingestion Core

A local JSONL/CSV ingestion prototype that streams input, preserves record digests and source references, and quarantines malformed, oversized, or policy-blocked records.

## Design goals
1. Stream local JSONL and CSV input without materializing the whole file.
2. Enforce aggregate file, per-record, and CSV field limits while reading.
3. Preserve a digest and source record reference for every emitted envelope.
4. Reject malformed or ambiguous structured input.
5. Distinguish an operator-supplied authorization assertion from actual authorization enforcement.
6. Quarantine suspicious, incomplete, or policy-blocked records.
7. Keep raw observations distinct from analyst claims and conclusions.

## Quick start
Python 3.10+, standard library only:
\`\`\`bash
python -m elite_ingestion.cli ingest examples/sample.jsonl --source-id demo --operator-asserts-authorized
python -m elite_ingestion.cli inspect output/accepted.jsonl output/quarantine.jsonl
python -m unittest discover -s tests -v
\`\`\`

The legacy \`--authorized\` flag remains an alias for compatibility. Both flags record only an operator assertion. They do **not** authenticate an operator, establish legal or contractual authority, or enforce a source registry or organizational policy. Production integrations must supply an independently enforced policy decision and audit reference.

## Resource limits
Defaults: 5 MiB aggregate input, 256 KiB per JSONL record / CSV row representation, 256 KiB per CSV field, and 256 CSV columns. Input is consumed incrementally. CSV quoted multiline fields are supported. Inputs that exceed the aggregate limit fail the import; oversized individual records are quarantined.

Malformed CSV quoting and fields that exceed the CSV parser limit fail the import with a controlled error. The CLI stages accepted/quarantine outputs and replaces the prior output files only after the input has been processed successfully, so parser or resource-limit failures do not leave newly truncated partial outputs.

The library exposes \`iter_ingest\` for bounded-memory processing. The older \`ingest\` convenience wrapper remains available but accumulates results in memory and should only be used for small inputs or tests.

## Identifiers and integrity
Each import receives a UUID import ID by default. Record IDs combine that import ID and source line number, avoiding collisions between repeated imports. A caller may supply a stable import ID when deliberately reproducing an import. SHA-256 digests cover the raw JSONL line or normalized CSV row representation; for CSV this is not a byte-for-byte digest of the original file row.

## Limitations
Instruction-injection markers are heuristics, not a complete detector or a security boundary. Hashes establish byte-level integrity relative to a digest, not truth, authorship, or legality. Duplicate detection is not semantic. A clean validation result does not establish source accuracy. This prototype does not implement a source registry, identity/authentication, legal review, signed manifests, network collection, crawling, or autonomous action.

## Related components
- [ELITE Protocol](https://github.com/midnightlolz31337/ELITE-Protocol)
- [ELITE Agent Commons](https://github.com/midnightlolz31337/ELITE-Agent-Commons)
- [Huffman Network Atlas](https://github.com/midnightlolz31337/Huffman-Network-Atlas)
