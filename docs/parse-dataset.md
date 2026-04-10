# Dataset Parsing Guide

This document is for:

- users who want to understand the incident pipeline end-to-end
- data pullers preparing training corpora for AI models

---

## 1) What the pipeline does

For each PoC test file, the pipeline does:

1. Parse PoC metadata and code.
2. Extract candidate contracts (AI first, fallback heuristics).
3. Resolve chain/address targets.
4. Fetch contract source, ABI, and bytecode (local artifacts/cache first, explorer fallback).
5. Run exploit analysis (`ai_analysis`) if AI is enabled and request succeeds.
6. Write normalized dataset records + contract artifacts.

Primary output: `data/output/dataset.json`

---

## 2) Source and provenance model

Each record is built from multiple sources:

- **PoC source**: raw Solidity test file (`poc_code`)
- **Contract resolution**: explorer APIs + local artifact cache
- **AI extraction**: identifies likely vulnerable/attacker/helper contracts
- **AI analysis**: explanation, root cause, steps, type, confidence

Trust model you should use for training:

- `poc_code` and resolved contract metadata are deterministic pipeline output.
- `ai_analysis` is model-generated and should be treated as weak/soft labels.
- `resolution.evidence` explains why a record is partial/failed/resolved.

---

## 3) `dataset.json` layout

Top level:

```json
{
  "version": "3.0.0",
  "generated_at": "...",
  "total_records": 698,
  "failed_ids": [],
  "records": []
}
```

During a long run, temporary checkpoints may include:

- `in_progress: true`
- `progress: { total, processed, success, failed, skipped, analyzed }`

Final file keeps the standard top-level dataset shape.

---

## 4) Record schema (`records[]`)

Main fields:

- `id`: stable incident ID
- `title`, `attack_title`
- `poc_code`: raw test/PoC source
- `resolution`: status + evidence trail
- `contracts_dir`: expanded artifact directory
- `contracts[]`: normalized contract entries
- `ai_analysis` (optional)
- `metadata`: parser/model/time info

### `resolution.status` (important)

Typical statuses:

- `resolved`: contracts resolved, no fetch errors
- `partial`: some verified, some not
- `fetch_failed`: explorer/network failures for at least one contract
- `unverified_contract`: no verified source found
- `chain_unsupported`: chain unavailable on current API tier
- `parse_failed`: extraction/parse did not produce usable targets

Use status filtering for training set quality control.

---

## 5) Contract schema (`records[].contracts[]`)

Each contract includes:

- identity: `address`, `role`
- chain: `chain.id`, `chain.name`
- verification: `verification_status`, `is_verified`
- availability:
  - `source_available`
  - `abi_available`
  - `bytecode_available`
- diagnostics: `fetch_error`
- artifact pointers: `artifact_dir`, `source_files[]`

If source is unavailable:

- `NO_SOURCE.txt` is written
- `bytecode.txt` is written when bytecode exists

---

## 6) `ai_analysis` schema

When present:

- `explanation`
- `root_cause`
- `attack_steps[]`
- `vulnerability_type`
- `confidence` (score + factors + reasoning)
- `mitigation[]` (only if mitigation generation is enabled)

If `ai_analysis` is missing/null, analysis failed or was disabled.

---

## 7) How to build training datasets

Recommended minimum-quality slice:

- keep records where:
  - `resolution.status` in `["resolved", "partial"]`
  - `ai_analysis != null`
  - at least one contract has `source_available == true`

Broader slice (include bytecode-only incidents):

- include records with `bytecode_available == true` even when source is missing
- keep `resolution.evidence` and `fetch_error` as quality/context features

Suggested supervised row format:

- Input:
  - `poc_code`
  - resolved contracts (address/role/chain/source-or-bytecode availability)
  - optional inlined source/bytecode from artifact files
- Labels:
  - `ai_analysis.vulnerability_type`
  - `ai_analysis.root_cause`
  - `ai_analysis.attack_steps`

---

## 8) `jq` queries for data pullers

Total incidents:

```bash
jq '.total_records' data/output/dataset.json
```

Incidents with analysis:

```bash
jq '[.records[] | select(.ai_analysis != null)] | length' data/output/dataset.json
```

High-quality training IDs:

```bash
jq -r '
  .records[]
  | select(.ai_analysis != null)
  | select(.resolution.status == "resolved" or .resolution.status == "partial")
  | select(any(.contracts[]; .source_available == true))
  | .id
' data/output/dataset.json
```

Incidents with bytecode-only contracts:

```bash
jq -r '
  .records[]
  | .id as $id
  | .contracts[]
  | select(.source_available == false and .bytecode_available == true)
  | [$id, .address, .chain.name] | @tsv
' data/output/dataset.json
```

Count by resolution status:

```bash
jq -r '.records[].resolution.status' data/output/dataset.json | sort | uniq -c
```

---

## 9) Contract artifact indexes

Use these for joining records to raw files:

- `data/contracts/manifest.json`: expanded filesystem index
- `data/contracts/contracts.compact.json`: compact deduplicated blob format

`contracts.compact.json` is best for model pipelines that want fewer filesystem operations.
