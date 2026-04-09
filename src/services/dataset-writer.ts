import { mkdir, writeFile, readFile } from "fs/promises";
import { join } from "path";
import { createHash } from "crypto";
import { logger } from "../lib/logger";
import type { DatasetRecord } from "../domain/vulnerability";
import type { Config } from "../config/env";

export interface WriterConfig {
  outputDir: string;
  idempotencyDir: string;
}

export interface Manifest {
  version: string;
  created_at: string;
  updated_at: string;
  total_records: number;
  failed_ids: string[];
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

    try {
      const existing = await readFile(
        join(this.config.outputDir, "manifest.json"),
        "utf-8",
      );
      this.manifest = JSON.parse(existing);
    } catch {
      // Start fresh
    }
  }

  async writeRecord(record: DatasetRecord): Promise<void> {
    // Not used in new flow
  }

  async markFailed(id: string, reason: string): Promise<void> {
    logger.warn(`Marking ${id} as failed: ${reason}`);
  }

  async finalize(records: DatasetRecord[], failedIds: string[]): Promise<void> {
    // Write single consolidated JSON file
    const dataPath = join(this.config.outputDir, "dataset.json");
    await writeFile(
      dataPath,
      JSON.stringify(records, null, 2),
      "utf-8",
    );

    logger.info(`Wrote ${records.length} records to dataset.json`);

    // Update manifest
    this.manifest.total_records = records.length;
    this.manifest.failed_ids = failedIds;
    this.manifest.updated_at = new Date().toISOString();

    const manifestPath = join(this.config.outputDir, "manifest.json");
    await writeFile(
      manifestPath,
      JSON.stringify(this.manifest, null, 2),
      "utf-8",
    );

    logger.info(`Dataset complete: ${records.length} records`);
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
}

export function createDatasetWriter(config: Partial<Config>): DatasetWriter {
  return new DatasetWriter({
    outputDir: config.output_dir ?? "./data/output",
    idempotencyDir: config.idempotency_dir ?? "./data/cache/idempotency",
  });
}

export function computeIdempotencyKey(
  pocCode: string,
  parserVersion: string,
  config: Partial<Config>,
): string {
  const input = `${pocCode.substring(0, 1000)}|${parserVersion}|${config.ai_enabled}|${config.ai_model}`;
  return createHash("sha256").update(input).digest("hex").substring(0, 16);
}