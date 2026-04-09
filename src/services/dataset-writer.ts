import { mkdir, writeFile, readFile, readdir } from 'fs/promises';
import { join, basename } from 'path';
import { createHash } from 'crypto';
import { logger } from '../lib/logger';
import type { DatasetRecord, ResolutionStatus } from '../domain/vulnerability';
import type { Config } from '../config/env';

export interface WriterConfig {
  outputDir: string;
  chunkSize: number;
  idempotencyDir: string;
}

export interface ManifestEntry {
  batch_file: string;
  record_count: number;
  records: string[];
}

export interface Manifest {
  version: string;
  created_at: string;
  updated_at: string;
  total_records: number;
  total_batches: number;
  batches: ManifestEntry[];
  failed_ids: string[];
}

export class DatasetWriter {
  private config: WriterConfig;
  private currentBatch: DatasetRecord[] = [];
  private batchCounter = 0;
  private failedIds: string[] = [];
  private manifest: Manifest;

  constructor(config: WriterConfig) {
    this.config = config;
    this.manifest = {
      version: '1.0.0',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      total_records: 0,
      total_batches: 0,
      batches: [],
      failed_ids: [],
    };
  }

  async initialize(): Promise<void> {
    await mkdir(this.config.outputDir, { recursive: true });
    await mkdir(this.config.idempotencyDir, { recursive: true });
    
    // Try to load existing manifest
    try {
      const existing = await readFile(join(this.config.outputDir, 'manifest.json'), 'utf-8');
      this.manifest = JSON.parse(existing);
    } catch {
      // No existing manifest, start fresh
    }
  }

  async writeRecord(record: DatasetRecord): Promise<void> {
    this.currentBatch.push(record);
    
    if (this.currentBatch.length >= this.config.chunkSize) {
      await this.flushBatch();
    }
  }

  async markFailed(id: string, reason: string): Promise<void> {
    logger.warn(`Marking ${id} as failed: ${reason}`);
    this.failedIds.push(id);
  }

  async flushBatch(): Promise<void> {
    if (this.currentBatch.length === 0) return;

    this.batchCounter++;
    const batchFile = `batch-${String(this.batchCounter).padStart(3, '0')}.json`;
    const batchPath = join(this.config.outputDir, batchFile);

    await writeFile(batchPath, JSON.stringify(this.currentBatch, null, 2), 'utf-8');
    
    const recordIds = this.currentBatch.map(r => r.id);
    
    this.manifest.batches.push({
      batch_file: batchFile,
      record_count: this.currentBatch.length,
      records: recordIds,
    });
    
    this.manifest.total_records += this.currentBatch.length;
    this.manifest.total_batches = this.batchCounter;
    this.manifest.updated_at = new Date().toISOString();

    logger.info(`Wrote batch ${this.batchCounter} with ${this.currentBatch.length} records`);
    
    this.currentBatch = [];
  }

  async finalize(): Promise<void> {
    // Flush any remaining records
    await this.flushBatch();
    
    // Add failed IDs to manifest
    this.manifest.failed_ids = this.failedIds;
    this.manifest.updated_at = new Date().toISOString();

    // Write manifest
    const manifestPath = join(this.config.outputDir, 'manifest.json');
    await writeFile(manifestPath, JSON.stringify(this.manifest, null, 2), 'utf-8');
    
    logger.info(`Dataset complete: ${this.manifest.total_records} records in ${this.manifest.total_batches} batches`);
    logger.info(`Failed: ${this.failedIds.length} records`);
  }

  getManifest(): Manifest {
    return this.manifest;
  }

  async hasIdempotencyKey(id: string): Promise<boolean> {
    try {
      await readFile(join(this.config.idempotencyDir, `${id}.json`), 'utf-8');
      return true;
    } catch {
      return false;
    }
  }

  async writeIdempotencyKey(id: string, data: object): Promise<void> {
    const keyPath = join(this.config.idempotencyDir, `${id}.json`);
    await writeFile(keyPath, JSON.stringify(data, null, 2), 'utf-8');
  }
}

export function createDatasetWriter(config: Partial<Config>): DatasetWriter {
  return new DatasetWriter({
    outputDir: config.output_dir ?? './data/output',
    chunkSize: config.chunk_size ?? 100,
    idempotencyDir: config.idempotency_dir ?? './data/cache/idempotency',
  });
}

export function computeIdempotencyKey(pocCode: string, parserVersion: string, config: Partial<Config>): string {
  const input = `${pocCode.substring(0, 1000)}|${parserVersion}|${config.ai_enabled}|${config.ai_model}`;
  return createHash('sha256').update(input).digest('hex').substring(0, 16);
}
