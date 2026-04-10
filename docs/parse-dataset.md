# Parse Dataset Output

This guide explains the output files and how to query them quickly.

## Files You Will Use

- `data/output/dataset.json`: main incident dataset
- `data/output/manifest.json`: run metadata
- `data/contracts/manifest.json`: contract artifact index
- `data/contracts/contracts.compact.json`: compact contract blob format (if generated)

## `dataset.json` Structure

Top-level shape:

```json
{
  "version": "3.0.0",
  "generated_at": "2026-04-10T06:22:29.139Z",
  "total_records": 20,
  "failed_ids": [],
  "records": []
}
```

During long runs, checkpoint writes may include:

```json
{
  "in_progress": true,
  "progress": {
    "total": 698,
    "processed": 120,
    "success": 118,
    "failed": 1,
    "skipped": 1,
    "analyzed": 80
  }
}
```

### Record shape (`records[]`)

Each record contains:

- `id`: stable incident ID
- `title`, `attack_title`
- `poc_code`: raw PoC Solidity test code
- `resolution`: status + evidence
- `contracts_dir`: where expanded files are stored
- `contracts[]`: normalized contract metadata
- `ai_analysis` (optional): analysis payload when AI succeeded
- `metadata`: parser/model/timestamp details

## Contract Object (`records[].contracts[]`)

Key fields:

- identity: `address`, `role`
- chain: `chain.id`, `chain.name`
- verification: `verification_status`, `is_verified`
- availability: `source_available`, `abi_available`, `bytecode_available`
- diagnostics: `fetch_error`
- artifacts: `artifact_dir`, `source_files[]`

If source is missing, `source_files` usually contains:

- `NO_SOURCE.txt`
- `bytecode.txt` (when bytecode was available)

## `ai_analysis` Object

When present:

- `explanation`
- `root_cause`
- `attack_steps[]`
- `vulnerability_type`
- `confidence`
- `mitigation[]` (only when mitigation is enabled)

If `ai_analysis` is null/missing, the record was parsed but AI analysis failed or was disabled.

## Useful `jq` Queries

### 1) Total incidents

```bash
jq '.total_records' data/output/dataset.json
```

### 2) How many have AI analysis

```bash
jq '[.records[] | select(.ai_analysis != null)] | length' data/output/dataset.json
```

### 3) IDs without AI analysis

```bash
jq -r '.records[] | select(.ai_analysis == null) | .id' data/output/dataset.json
```

### 4) Count by resolution status

```bash
jq -r '.records[].resolution.status' data/output/dataset.json | sort | uniq -c
```

### 5) Contracts with no source but bytecode present

```bash
jq -r '
  .records[]
  | .id as $id
  | .contracts[]
  | select(.source_available == false and .bytecode_available == true)
  | [$id, .address, .chain.name] | @tsv
' data/output/dataset.json
```

### 6) Incidents by chain

```bash
jq -r '
  .records[]
  | .contracts[]
  | .chain.name
' data/output/dataset.json | sort | uniq -c | sort -nr
```

## `data/contracts/manifest.json`

Use this when you want direct mapping from incident -> contract -> artifact files.

It is the index for expanded contract files and includes:

- `pocs[]`
  - `id`, `contracts_dir`
  - `contracts[]`
    - `address`, `chain_id`, `verification_status`
    - `artifact_dir`, `source_files[]`

## Compact Contracts File (`contracts.compact.json`)

If you run compaction, this file stores contract source/bytecode in a deduplicated blob format:

- `pocs[]` references files by `blob_id`
- `blobs[]` contains full text content once per unique hash

This is useful for low file churn in CI and Git workflows.

