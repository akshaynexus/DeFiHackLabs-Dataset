# DeFiHackLabs Dataset Pipeline

Builds a machine-readable exploit dataset from DeFiHackLabs PoC tests.

## Quickstart

```bash
bun install
cp .env.example .env
```

Set required `.env` values:

- `ETHERSCAN_API_KEY`
- `AI_ENABLED=true` (optional, but recommended for labels)
- one provider key matching your model:
  - `GEMINI_API_KEY`
  - `OPENROUTER_API_KEY`
  - `CROF_API_KEY`

Run:

```bash
bun run start
```

## Output

- `data/output/dataset.json` - final training-ready incident records
- `data/output/manifest.json` - run metadata and progress snapshots
- `data/contracts/manifest.json` - index of contract artifact files
- `data/contracts/<incident-id>/...` - expanded contract source/bytecode files

## Docs

- Dataset structure + parsing: `docs/parse-dataset.md`
- Compaction flow:
  - `bun run compact:data`
  - `bun run compact:data:prune`

## Common Toggles

- `IDEMPOTENCY_STRATEGY=skip|overwrite`
- `AI_ENABLE_MITIGATION=true|false`
- `TEST_LIMIT=<n>`
- `PIPELINE_PARALLEL`, `FETCH_PARALLEL`, `AI_PARALLEL`
