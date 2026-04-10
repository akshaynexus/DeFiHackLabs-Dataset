# DeFiHackLabs Dataset Pipeline

Generate a structured exploit dataset from DeFiHackLabs PoC tests, resolve contract data, and run optional AI extraction/analysis.

## Quick Start

```bash
bun install
cp .env.example .env
```

Set required values in `.env`:

- `ETHERSCAN_API_KEY`
- `AI_ENABLED=true` (if using AI)
- provider key for your model (`GEMINI_API_KEY`, `OPENROUTER_API_KEY`, or `CROF_API_KEY`)

Run:

```bash
bun run start
```

## Output Files

- `data/output/dataset.json`: main dataset
- `data/output/manifest.json`: run metadata/progress snapshot
- `data/contracts/manifest.json`: contract artifacts index
- `data/contracts/<incident-id>/...`: expanded source/bytecode artifacts

Detailed parsing guide: [docs/parse-dataset.md](/Users/akshaycm/Documents/GitRepos/DeFiHackLabs-Dataset/docs/parse-dataset.md)

## Compaction (Reduce File Churn)

Create compact contracts data:

```bash
bun run compact:data
```

Create compact data and prune expanded/cache files:

```bash
bun run compact:data:prune
```

Compaction outputs:

- `data/contracts/contracts.compact.json`
- `data/output/compact-summary.json`

## Common Toggles

- `IDEMPOTENCY_STRATEGY=skip|overwrite`
- `AI_ENABLE_MITIGATION=true|false`
- `TEST_LIMIT=<n>`
- `PIPELINE_PARALLEL`, `FETCH_PARALLEL`, `AI_PARALLEL`

