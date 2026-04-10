# DeFiHackLabs Dataset Pipeline

Builds a structured exploit dataset from PoC Solidity files, resolves contracts/source/bytecode, and runs AI extraction + analysis.

## 1) Install

```bash
bun install
```

## 2) Configure

Copy `.env.example` to `.env`, then set:

- `ETHERSCAN_API_KEY`
- AI provider key for your selected model (`GEMINI_API_KEY`, `OPENROUTER_API_KEY`, or `CROF_API_KEY`)
- `AI_ENABLED=true` if you want AI extraction/analysis

Common toggles:

- `AI_ENABLE_MITIGATION=false` to disable mitigation generation
- `IDEMPOTENCY_STRATEGY=skip|overwrite`
- `TEST_LIMIT=<n>` for partial runs

## 3) Run Pipeline

```bash
bun run start
```

Outputs:

- `data/output/dataset.json` (main dataset)
- `data/output/manifest.json` (run summary)
- `data/contracts/manifest.json` (contract artifact index)
- `data/contracts/<incident-id>/...` (expanded contract files)

## 4) Compact Data Layout (reduce file churn)

When you want fewer files for commits/workflows, compact the expanded contracts tree into a single file.

### Safe mode (no deletes)

```bash
bun run compact:data
```

Creates:

- `data/contracts/contracts.compact.json` (single compact contracts artifact)
- `data/output/compact-summary.json` (counts/summary)

### Prune mode (aggressive cleanup)

```bash
bun run compact:data:prune
```

In addition to creating compact outputs, it prunes noisy trees:

- `data/cache/contracts/*`
- `data/cache/idempotency/*`
- expanded `data/contracts/*` folders

After prune, kept files are:

- `data/contracts/manifest.json`
- `data/contracts/contracts.compact.json`
- dataset files in `data/output/*`

## 5) Recommended Workflow

1. Run pipeline: `bun run start`
2. Review `data/output/dataset.json`
3. Compact for commit/CI: `bun run compact:data`
4. Use prune mode only when you explicitly want to remove expanded/cache files

## Notes

- If `IDEMPOTENCY_STRATEGY=skip`, records without required AI analysis are reprocessed.
- If source is unavailable, bytecode (when available) is included in AI analysis context.
