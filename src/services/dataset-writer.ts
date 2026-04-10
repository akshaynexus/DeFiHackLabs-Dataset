import { createHash } from "crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "fs/promises";
import { dirname, join } from "path";

import type { Config } from "../config/env";
import { logger } from "../lib/logger";
import type { DatasetRecord } from "../domain/vulnerability";

export interface WriterConfig {
  outputDir: string;
  idempotencyDir: string;
  contractsDir: string;
  aiEnableMitigation: boolean;
}

export interface Manifest {
  version: string;
  created_at: string;
  updated_at: string;
  total_records: number;
  failed_ids: string[];
}

export interface ProgressSnapshotStats {
  total: number;
  processed: number;
  success: number;
  failed: number;
  skipped: number;
  analyzed: number;
}

interface ContractArtifact {
  artifact_dir: string;
  source_files: string[];
}

interface ContractsArtifactsOutput {
  poc_dir: string;
  contract_artifacts: ContractArtifact[];
}

export class DatasetWriter {
  private config: WriterConfig;
  private manifest: Manifest;

  constructor(config: WriterConfig) {
    this.config = config;
    this.manifest = {
      version: "1.0.0",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      total_records: 0,
      failed_ids: [],
    };
  }

  async initialize(): Promise<void> {
    await mkdir(this.config.outputDir, { recursive: true });
    await mkdir(this.config.idempotencyDir, { recursive: true });
    await mkdir(this.config.contractsDir, { recursive: true });
    await this.cleanupLegacyContractsArtifacts();

    try {
      const existing = await readFile(
        join(this.config.outputDir, "manifest.json"),
        "utf-8",
      );
      this.manifest = JSON.parse(existing);
    } catch {
      // Start fresh.
    }
  }

  async writeRecord(_record: DatasetRecord): Promise<void> {
    // Not used in current flow.
  }

  async markFailed(id: string, reason: string): Promise<void> {
    logger.warn(`Marking ${id} as failed: ${reason}`);
  }

  async writeProgressSnapshot(
    records: DatasetRecord[],
    failedIds: string[],
    stats: ProgressSnapshotStats,
  ): Promise<void> {
    const output = {
      version: "3.0.0",
      generated_at: new Date().toISOString(),
      total_records: records.length,
      failed_ids: failedIds,
      in_progress: true,
      progress: stats,
      records: records.map((record) => this.toCheckpointRecord(record)),
    };

    const dataPath = join(this.config.outputDir, "dataset.json");
    await writeFile(dataPath, JSON.stringify(output, null, 2), "utf-8");

    this.manifest.total_records = records.length;
    this.manifest.failed_ids = failedIds;
    this.manifest.updated_at = new Date().toISOString();

    const manifestPath = join(this.config.outputDir, "manifest.json");
    await writeFile(
      manifestPath,
      JSON.stringify(
        {
          ...this.manifest,
          in_progress: true,
          progress: stats,
        },
        null,
        2,
      ),
      "utf-8",
    );
  }

  async finalize(records: DatasetRecord[], failedIds: string[]): Promise<void> {
    const bundledRecords: Array<{
      cleanRecord: ReturnType<DatasetWriter["toCleanRecord"]>;
      contractsManifestEntry: ReturnType<DatasetWriter["toContractsManifestEntry"]>;
    }> = [];
    for (const record of records) {
      const contractArtifacts = await this.writeContractsArtifacts(record);
      bundledRecords.push({
        cleanRecord: this.toCleanRecord(record, contractArtifacts),
        contractsManifestEntry: this.toContractsManifestEntry(
          record,
          contractArtifacts,
        ),
      });
    }

    const cleanedRecords = bundledRecords.map((item) => item.cleanRecord);

    const output = {
      version: "3.0.0",
      generated_at: new Date().toISOString(),
      total_records: cleanedRecords.length,
      failed_ids: failedIds,
      records: cleanedRecords,
    };

    const dataPath = join(this.config.outputDir, "dataset.json");
    const existingRecordCount = await this.readExistingDatasetRecordCount(dataPath);
    if (cleanedRecords.length === 0 && existingRecordCount > 0) {
      logger.warn(
        `Refusing to overwrite existing dataset (${existingRecordCount} records) with empty output`,
      );
      return;
    }
    await this.backupExistingDatasetIfPresent(dataPath);
    await writeFile(dataPath, JSON.stringify(output, null, 2), "utf-8");

    logger.info(`Wrote ${cleanedRecords.length} records to dataset.json`);

    const contractsManifestPath = join(this.config.contractsDir, "manifest.json");
    const existingManifestPocs =
      await this.readExistingContractsManifestPocs(contractsManifestPath);
    const mergedById = new Map(
      existingManifestPocs.map((entry) => [entry.id, entry] as const),
    );
    for (const item of bundledRecords) {
      mergedById.set(item.contractsManifestEntry.id, item.contractsManifestEntry);
    }
    const mergedPocs = Array.from(mergedById.values());

    const contractsManifest = {
      version: "1.0.0",
      generated_at: new Date().toISOString(),
      contracts_root: this.toPosixPath(this.config.contractsDir),
      total_pocs: mergedPocs.length,
      total_contracts: mergedPocs.reduce(
        (sum, entry) => sum + entry.contracts.length,
        0,
      ),
      pocs: mergedPocs,
    };

    await writeFile(
      contractsManifestPath,
      JSON.stringify(contractsManifest, null, 2),
      "utf-8",
    );
    logger.info("Wrote centralized contracts manifest.json");

    this.manifest.total_records = cleanedRecords.length;
    this.manifest.failed_ids = failedIds;
    this.manifest.updated_at = new Date().toISOString();

    const manifestPath = join(this.config.outputDir, "manifest.json");
    await writeFile(manifestPath, JSON.stringify(this.manifest, null, 2), "utf-8");

    logger.info(`Dataset complete: ${cleanedRecords.length} records`);
    if (failedIds.length > 0) {
      logger.info(`Failed: ${failedIds.length} records`);
    }
  }

  getManifest(): Manifest {
    return this.manifest;
  }

  async hasIdempotencyKey(id: string): Promise<boolean> {
    try {
      await readFile(join(this.config.idempotencyDir, `${id}.json`), "utf-8");
      return true;
    } catch {
      return false;
    }
  }

  async writeIdempotencyKey(id: string, data: object): Promise<void> {
    const keyPath = join(this.config.idempotencyDir, `${id}.json`);
    await writeFile(keyPath, JSON.stringify(data, null, 2), "utf-8");
  }

  private toCleanRecord(
    record: DatasetRecord,
    artifacts: ContractsArtifactsOutput,
  ) {
    return {
      id: record.id,
      title: record.title,
      attack_title: record.attack_title,
      poc_code: record.testcase,
      resolution: record.resolution,
      contracts_dir: artifacts.poc_dir,
      contracts: record.contracts.map((contract, idx) => ({
        address: contract.address,
        role: contract.role,
        chain: {
          id: contract.chain_id,
          name: contract.chain_name,
        },
        verification_status: contract.verification_status,
        is_verified: contract.is_verified,
        contract_name: contract.contract_name ?? null,
        compiler_version: contract.compiler_version ?? null,
        source_available: Boolean(contract.source_code),
        abi_available: Boolean(contract.abi),
        bytecode_available: Boolean(contract.bytecode),
        source_hint: contract.source_hint,
        explorer_url: contract.explorer_url,
        proxy: contract.proxy,
        fetch_error: contract.fetch_error ?? null,
        artifact_dir: artifacts.contract_artifacts[idx]?.artifact_dir ?? null,
        source_files: artifacts.contract_artifacts[idx]?.source_files ?? [],
      })),
      ai_analysis: this.toCleanAnalysis(record.ai_analysis),
      metadata: record.metadata,
    };
  }

  private toCheckpointRecord(record: DatasetRecord) {
    return {
      id: record.id,
      title: record.title,
      attack_title: record.attack_title,
      poc_code: record.testcase,
      resolution: record.resolution,
      contracts_dir: this.toPosixPath(join(this.config.contractsDir, record.id)),
      contracts: record.contracts.map((contract) => ({
        address: contract.address,
        role: contract.role,
        chain: {
          id: contract.chain_id,
          name: contract.chain_name,
        },
        verification_status: contract.verification_status,
        is_verified: contract.is_verified,
        contract_name: contract.contract_name ?? null,
        compiler_version: contract.compiler_version ?? null,
        source_available: Boolean(contract.source_code),
        abi_available: Boolean(contract.abi),
        bytecode_available: Boolean(contract.bytecode),
        source_hint: contract.source_hint,
        explorer_url: contract.explorer_url,
        proxy: contract.proxy,
        fetch_error: contract.fetch_error ?? null,
        artifact_dir: null,
        source_files: [],
      })),
      ai_analysis: this.toCleanAnalysis(record.ai_analysis),
      metadata: record.metadata,
    };
  }

  private toContractsManifestEntry(
    record: DatasetRecord,
    artifacts: ContractsArtifactsOutput,
  ) {
    return {
      id: record.id,
      title: record.title,
      attack_title: record.attack_title,
      contracts_dir: artifacts.poc_dir,
      contracts: record.contracts.map((contract, idx) => ({
        address: contract.address,
        role: contract.role,
        chain_id: contract.chain_id,
        chain_name: contract.chain_name,
        contract_name: contract.contract_name ?? null,
        verification_status: contract.verification_status,
        fetch_error: contract.fetch_error ?? null,
        artifact_dir: artifacts.contract_artifacts[idx]?.artifact_dir ?? null,
        source_files: artifacts.contract_artifacts[idx]?.source_files ?? [],
      })),
    };
  }

  private toCleanAnalysis(analysis: DatasetRecord["ai_analysis"]) {
    if (!analysis) return undefined;
    if (this.config.aiEnableMitigation) return analysis;
    const { mitigation: _mitigation, ...rest } = analysis;
    return rest;
  }

  private async writeContractsArtifacts(
    record: DatasetRecord,
  ): Promise<ContractsArtifactsOutput> {
    const pocDir = join(this.config.contractsDir, record.id);
    const contractsRoot = join(pocDir, "contracts");
    const legacyFlatFile = join(this.config.contractsDir, `${record.id}.sol`);

    await rm(pocDir, { recursive: true, force: true });
    await rm(legacyFlatFile, { force: true });
    await mkdir(contractsRoot, { recursive: true });

    const contractArtifacts: ContractArtifact[] = [];

    for (const [i, contract] of record.contracts.entries()) {
      const ordinal = String(i + 1).padStart(2, "0");
      const shortAddress = contract.address.replace(/^0x/i, "").slice(0, 8);
      const role = this.sanitizeSegment(contract.role);
      const name = this.sanitizeSegment(contract.contract_name ?? "contract");
      const folderName = `${ordinal}_${role}_${shortAddress}_${name}`;
      const contractDir = join(contractsRoot, folderName);

      await mkdir(contractDir, { recursive: true });

      const sourceUnits = this.parseSourceUnits(contract.source_code);
      const sourceFiles: string[] = [];

      if (sourceUnits.length === 0) {
        const bytecodeFile = join(contractDir, "bytecode.txt");
        const noSourceFile = join(contractDir, "NO_SOURCE.txt");
        const bytecode = contract.bytecode?.trim();

        if (bytecode && bytecode.length > 0) {
          await writeFile(
            bytecodeFile,
            `${bytecode}\n`,
            "utf-8",
          );
          sourceFiles.push(this.toPosixPath(bytecodeFile));
        }

        await writeFile(
          noSourceFile,
          `No verified source available for ${contract.address}\n${
            bytecode && bytecode.length > 0
              ? `Bytecode saved at ${this.toPosixPath(bytecodeFile)}\n`
              : "Bytecode unavailable\n"
          }`,
          "utf-8",
        );
        sourceFiles.push(this.toPosixPath(noSourceFile));
      } else {
        for (const [sourceIndex, unit] of sourceUnits.entries()) {
          const normalizedPath = this.normalizeSourcePath(unit.path, sourceIndex);
          const outputPath =
            sourceUnits.length === 1 && normalizedPath === "flattened.sol"
              ? join(contractDir, "source.sol")
              : join(contractDir, "sources", normalizedPath);

          await mkdir(dirname(outputPath), { recursive: true });
          await writeFile(outputPath, unit.content, "utf-8");
          sourceFiles.push(this.toPosixPath(outputPath));
        }
      }

      contractArtifacts.push({
        artifact_dir: this.toPosixPath(contractDir),
        source_files: sourceFiles,
      });
    }

    return {
      poc_dir: this.toPosixPath(pocDir),
      contract_artifacts: contractArtifacts,
    };
  }

  private parseSourceUnits(
    sourceCode: string | undefined,
  ): Array<{ path: string; content: string }> {
    if (!sourceCode || sourceCode.trim().length === 0) return [];

    const raw = sourceCode.trim();
    const parsed =
      this.tryParseSourceObject(raw) ??
      this.tryParseSourceObject(
        raw.startsWith("{{") && raw.endsWith("}}") ? raw.slice(1, -1) : raw,
      );

    if (!parsed || typeof parsed !== "object") {
      return [{ path: "flattened.sol", content: raw }];
    }

    const payload = parsed as Record<string, unknown>;
    const fromSources = this.extractFromSourcesObject(payload);
    if (fromSources.length > 0) return fromSources;

    const fromDirectMap = this.extractFromDirectContentMap(payload);
    if (fromDirectMap.length > 0) return fromDirectMap;

    return [{ path: "flattened.sol", content: raw }];
  }

  private tryParseSourceObject(source: string): unknown | null {
    try {
      return JSON.parse(source);
    } catch {
      return null;
    }
  }

  private extractFromSourcesObject(
    payload: Record<string, unknown>,
  ): Array<{ path: string; content: string }> {
    const sources = payload.sources;
    if (!sources || typeof sources !== "object") return [];

    const result: Array<{ path: string; content: string }> = [];
    for (const [path, value] of Object.entries(sources as Record<string, unknown>)) {
      if (!value || typeof value !== "object") continue;
      const content = (value as { content?: unknown }).content;
      if (typeof content === "string" && content.trim().length > 0) {
        result.push({ path, content });
      }
    }
    return result;
  }

  private extractFromDirectContentMap(
    payload: Record<string, unknown>,
  ): Array<{ path: string; content: string }> {
    const result: Array<{ path: string; content: string }> = [];
    for (const [path, value] of Object.entries(payload)) {
      if (!value || typeof value !== "object") continue;
      const content = (value as { content?: unknown }).content;
      if (typeof content === "string" && content.trim().length > 0) {
        result.push({ path, content });
      }
    }
    return result;
  }

  private normalizeSourcePath(path: string, fallbackIndex: number): string {
    const normalized = path.replace(/\\/g, "/").replace(/^[A-Za-z]:/, "");
    const parts = normalized
      .split("/")
      .filter((part) => part.length > 0 && part !== "." && part !== "..")
      .map((part) => this.sanitizeFileName(part));

    const joined = parts.join("/");
    if (joined.length > 0) return joined;
    return `source_${fallbackIndex + 1}.sol`;
  }

  private sanitizeSegment(value: string): string {
    const cleaned = value
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "_")
      .replace(/^_+|_+$/g, "");
    return cleaned.length > 0 ? cleaned.slice(0, 60) : "item";
  }

  private sanitizeFileName(value: string): string {
    const cleaned = value
      .replace(/[<>:"|?*\x00-\x1F]/g, "_")
      .replace(/\s+/g, "_")
      .replace(/^_+|_+$/g, "");
    return cleaned.length > 0 ? cleaned.slice(0, 120) : "file.sol";
  }

  private toPosixPath(path: string): string {
    return path.replace(/\\/g, "/");
  }

  private async backupExistingDatasetIfPresent(dataPath: string): Promise<void> {
    try {
      const existingRaw = await readFile(dataPath, "utf-8");
      const existingParsed = JSON.parse(existingRaw) as unknown;
      const existingRecords = Array.isArray(existingParsed)
        ? existingParsed
        : existingParsed &&
            typeof existingParsed === "object" &&
            Array.isArray((existingParsed as { records?: unknown[] }).records)
          ? (existingParsed as { records: unknown[] }).records
          : [];

      if (existingRecords.length > 0) {
        const backupPath = join(this.config.outputDir, "dataset.backup.json");
        await writeFile(backupPath, existingRaw, "utf-8");
      }
    } catch {
      // No existing dataset to back up.
    }
  }

  private async cleanupLegacyContractsArtifacts(): Promise<void> {
    const legacyNames = new Set(["README.md", "index.json", "metadata.json"]);
    const keepPath = this.toPosixPath(join(this.config.contractsDir, "manifest.json"));

    const walk = async (dir: string): Promise<void> => {
      const entries = await readdir(dir, { withFileTypes: true });
      await Promise.all(
        entries.map(async (entry) => {
          const fullPath = join(dir, entry.name);
          if (entry.isDirectory()) {
            await walk(fullPath);
            return;
          }
          if (!legacyNames.has(entry.name)) {
            return;
          }
          const normalized = this.toPosixPath(fullPath);
          if (normalized === keepPath) {
            return;
          }
          await rm(fullPath, { force: true });
        }),
      );
    };

    await walk(this.config.contractsDir);
  }

  private async readExistingContractsManifestPocs(
    manifestPath: string,
  ): Promise<Array<{ id: string; contracts: unknown[] } & Record<string, unknown>>> {
    try {
      const raw = await readFile(manifestPath, "utf-8");
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object") return [];
      const pocs = (parsed as { pocs?: unknown[] }).pocs;
      if (!Array.isArray(pocs)) return [];
      return pocs.filter(
        (entry): entry is { id: string; contracts: unknown[] } & Record<string, unknown> =>
          Boolean(
            entry &&
              typeof entry === "object" &&
              typeof (entry as { id?: unknown }).id === "string" &&
              Array.isArray((entry as { contracts?: unknown[] }).contracts),
          ),
      );
    } catch {
      return [];
    }
  }

  private async readExistingDatasetRecordCount(dataPath: string): Promise<number> {
    try {
      const existingRaw = await readFile(dataPath, "utf-8");
      const existingParsed = JSON.parse(existingRaw) as unknown;
      if (Array.isArray(existingParsed)) return existingParsed.length;
      if (
        existingParsed &&
        typeof existingParsed === "object" &&
        Array.isArray((existingParsed as { records?: unknown[] }).records)
      ) {
        return (existingParsed as { records: unknown[] }).records.length;
      }
      return 0;
    } catch {
      return 0;
    }
  }
}

export function createDatasetWriter(config: Partial<Config>): DatasetWriter {
  return new DatasetWriter({
    outputDir: config.output_dir ?? "./data/output",
    idempotencyDir: config.idempotency_dir ?? "./data/cache/idempotency",
    contractsDir: config.contracts_dir ?? "./data/contracts",
    aiEnableMitigation: config.ai_enable_mitigation ?? true,
  });
}

export function computeIdempotencyKey(
  pocCode: string,
  parserVersion: string,
  config: Partial<Config>,
): string {
  const aiModelFingerprint = `${config.ai_extraction_model ?? ""}|${config.ai_analysis_model ?? ""}`;
  const input = `${pocCode.substring(0, 1000)}|${parserVersion}|${config.ai_enabled}|${config.ai_enable_mitigation}|${aiModelFingerprint}`;
  return createHash("sha256").update(input).digest("hex").substring(0, 16);
}
