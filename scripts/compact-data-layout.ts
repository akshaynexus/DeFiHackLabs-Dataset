import { createHash } from "crypto";
import { mkdir, readdir, readFile, rm, writeFile } from "fs/promises";
import { basename, isAbsolute, join, resolve } from "path";

interface DatasetEnvelope {
  version?: string;
  generated_at?: string;
  total_records?: number;
  failed_ids?: string[];
  records?: unknown[];
}

interface ContractsManifest {
  version?: string;
  generated_at?: string;
  contracts_root?: string;
  total_pocs?: number;
  total_contracts?: number;
  pocs?: ContractsManifestPOC[];
}

interface ContractsManifestPOC {
  id: string;
  title?: string;
  attack_title?: string;
  contracts_dir?: string;
  contracts?: ContractsManifestContract[];
}

interface ContractsManifestContract {
  address: string;
  role?: string;
  chain_id?: number;
  chain_name?: string;
  contract_name?: string | null;
  verification_status?: string;
  fetch_error?: string | null;
  artifact_dir?: string | null;
  source_files?: string[];
}

type BlobKind = "solidity" | "bytecode" | "note" | "file";

interface CompactBlob {
  id: string;
  kind: BlobKind;
  content: string;
  size_bytes: number;
}

interface CompactFileRef {
  path: string;
  blob_id: string;
  kind: BlobKind;
  size_bytes: number;
}

interface CompactContract {
  address: string;
  role: string | null;
  chain_id: number | null;
  chain_name: string | null;
  contract_name: string | null;
  verification_status: string | null;
  fetch_error: string | null;
  artifact_dir: string | null;
  files: CompactFileRef[];
}

interface CompactPOC {
  id: string;
  title: string | null;
  attack_title: string | null;
  contracts_dir: string | null;
  contracts: CompactContract[];
}

interface CompactContractsFile {
  version: string;
  generated_at: string;
  source: {
    dataset: string;
    contracts_manifest: string;
  };
  totals: {
    pocs: number;
    contracts: number;
    source_files: number;
    unique_blobs: number;
    blob_bytes: number;
  };
  pocs: CompactPOC[];
  blobs: CompactBlob[];
}

interface CompactSummary {
  generated_at: string;
  dataset_records: number;
  compact_pocs: number;
  compact_contracts: number;
  compact_source_files: number;
  compact_unique_blobs: number;
  compact_blob_bytes: number;
  pruned: boolean;
}

const cwd = process.cwd();
const dataDir = resolve(cwd, "data");
const outputDir = resolve(dataDir, "output");
const contractsDir = resolve(dataDir, "contracts");
const cacheDir = resolve(dataDir, "cache");

const datasetPath = resolve(outputDir, "dataset.json");
const contractsManifestPath = resolve(contractsDir, "manifest.json");
const compactContractsPath = resolve(contractsDir, "contracts.compact.json");
const compactSummaryPath = resolve(outputDir, "compact-summary.json");

function resolveFromCwd(pathLike: string): string {
  if (isAbsolute(pathLike)) {
    return pathLike;
  }
  return resolve(cwd, pathLike);
}

function toPosix(pathLike: string): string {
  return pathLike.replace(/\\/g, "/");
}

function detectKind(pathLike: string): BlobKind {
  const normalized = pathLike.toLowerCase();
  if (normalized.endsWith(".sol")) return "solidity";
  if (normalized.endsWith("bytecode.txt")) return "bytecode";
  if (normalized.endsWith("no_source.txt")) return "note";
  return "file";
}

function sha256(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

async function readJsonFile<T>(path: string): Promise<T> {
  const raw = await readFile(path, "utf-8");
  return JSON.parse(raw) as T;
}

async function readTextIfExists(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return null;
  }
}

async function pruneCacheTrees(): Promise<void> {
  await rm(resolve(cacheDir, "contracts"), { recursive: true, force: true });
  await rm(resolve(cacheDir, "idempotency"), { recursive: true, force: true });
  await mkdir(resolve(cacheDir, "contracts"), { recursive: true });
  await mkdir(resolve(cacheDir, "idempotency"), { recursive: true });
}

async function pruneContractsTreeKeepCompact(): Promise<void> {
  const entries = await readdir(contractsDir, { withFileTypes: true });
  const keep = new Set(["manifest.json", basename(compactContractsPath)]);

  await Promise.all(
    entries.map(async (entry) => {
      if (keep.has(entry.name)) return;
      await rm(join(contractsDir, entry.name), { recursive: true, force: true });
    }),
  );
}

async function main() {
  const prune = process.argv.includes("--prune");

  const dataset = await readJsonFile<DatasetEnvelope>(datasetPath);
  const contractsManifest = await readJsonFile<ContractsManifest>(contractsManifestPath);

  const pocsInput = Array.isArray(contractsManifest.pocs)
    ? contractsManifest.pocs
    : [];

  const blobById = new Map<string, CompactBlob>();
  const compactPocs: CompactPOC[] = [];
  let sourceFileCount = 0;
  let contractCount = 0;

  for (const poc of pocsInput) {
    const contractsInput = Array.isArray(poc.contracts) ? poc.contracts : [];
    const compactContracts: CompactContract[] = [];

    for (const contract of contractsInput) {
      contractCount++;
      const sourceFiles = Array.isArray(contract.source_files)
        ? contract.source_files
        : [];
      const fileRefs: CompactFileRef[] = [];

      for (const sourceFilePath of sourceFiles) {
        const absPath = resolveFromCwd(sourceFilePath);
        const content = await readTextIfExists(absPath);
        if (content === null) continue;

        sourceFileCount++;
        const kind = detectKind(sourceFilePath);
        const id = sha256(content);
        const sizeBytes = Buffer.byteLength(content, "utf-8");
        if (!blobById.has(id)) {
          blobById.set(id, {
            id,
            kind,
            content,
            size_bytes: sizeBytes,
          });
        }

        fileRefs.push({
          path: toPosix(sourceFilePath),
          blob_id: id,
          kind,
          size_bytes: sizeBytes,
        });
      }

      compactContracts.push({
        address: contract.address,
        role: contract.role ?? null,
        chain_id: typeof contract.chain_id === "number" ? contract.chain_id : null,
        chain_name: contract.chain_name ?? null,
        contract_name: contract.contract_name ?? null,
        verification_status: contract.verification_status ?? null,
        fetch_error: contract.fetch_error ?? null,
        artifact_dir: contract.artifact_dir ?? null,
        files: fileRefs,
      });
    }

    compactPocs.push({
      id: poc.id,
      title: poc.title ?? null,
      attack_title: poc.attack_title ?? null,
      contracts_dir: poc.contracts_dir ?? null,
      contracts: compactContracts,
    });
  }

  const blobs = Array.from(blobById.values()).sort((a, b) =>
    a.id.localeCompare(b.id),
  );
  const blobBytes = blobs.reduce((sum, blob) => sum + blob.size_bytes, 0);

  const compactContracts: CompactContractsFile = {
    version: "1.0.0",
    generated_at: new Date().toISOString(),
    source: {
      dataset: toPosix(datasetPath),
      contracts_manifest: toPosix(contractsManifestPath),
    },
    totals: {
      pocs: compactPocs.length,
      contracts: contractCount,
      source_files: sourceFileCount,
      unique_blobs: blobs.length,
      blob_bytes: blobBytes,
    },
    pocs: compactPocs,
    blobs,
  };

  await mkdir(contractsDir, { recursive: true });
  await mkdir(outputDir, { recursive: true });
  await writeFile(
    compactContractsPath,
    JSON.stringify(compactContracts, null, 2),
    "utf-8",
  );

  if (prune) {
    await pruneCacheTrees();
    await pruneContractsTreeKeepCompact();
  }

  const summary: CompactSummary = {
    generated_at: new Date().toISOString(),
    dataset_records: Array.isArray(dataset.records) ? dataset.records.length : 0,
    compact_pocs: compactPocs.length,
    compact_contracts: contractCount,
    compact_source_files: sourceFileCount,
    compact_unique_blobs: blobs.length,
    compact_blob_bytes: blobBytes,
    pruned: prune,
  };

  await writeFile(compactSummaryPath, JSON.stringify(summary, null, 2), "utf-8");

  console.log(
    `[compact-data-layout] wrote ${toPosix(compactContractsPath)} (${compactPocs.length} pocs, ${contractCount} contracts, ${blobs.length} unique blobs)`,
  );
  if (prune) {
    console.log(
      "[compact-data-layout] pruned data/cache/{contracts,idempotency} and expanded data/contracts tree",
    );
  }
}

main().catch((error) => {
  console.error("[compact-data-layout] failed:", error);
  process.exit(1);
});

