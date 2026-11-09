# ELITE Ingestion Core

A provenance-first, local ingestion and validation engine with quarantine, data-quality controls, and poisoning defenses.

## Design goals
1. Accept bounded local JSONL and CSV inputs only.
2. Preserve a digest and source record reference for every observation.
3. Reject malformed or ambiguous structured input.
4. Separate source authorization from data validity.
5. Quarantine suspicious, incomplete, or policy-blocked records.
6. Keep raw observations distinct from analyst claims and conclusions.

## Quick start
Python 3.10+, standard library only:
```bash
python -m elite_ingestion.cli ingest examples/sample.jsonl --source-id demo --authorized
python -m elite_ingestion.cli inspect output/accepted.jsonl output/quarantine.jsonl
python -m unittest discover -s tests
```
The `--authorized` flag is an operator assertion for this local demonstration, not a legal or contractual authorization system.

## Limitations
Injection indicators are heuristics, not a complete detector. Hashes establish byte-level integrity relative to a digest, not truth. Duplicate detection is exact-record only. A clean validation result does not establish source accuracy. No network collection, crawling, private-person targeting, or autonomous action is included.

## Related components
- [ELITE Protocol](https://github.com/midnightlolz31337/ELITE-Protocol)
- [ELITE Agent Commons](https://github.com/midnightlolz31337/ELITE-Agent-Commons)
- [Huffman Network Atlas](https://github.com/midnightlolz31337/Huffman-Network-Atlas)
