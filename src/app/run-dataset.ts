import { readFile } from "fs/promises";
import { join } from "path";
import * as cliProgress from "cli-progress";

import {
  createAIClient,
  parseFoundryChains,
  type AIClient,
  type ChainContext,
  type ExtractedContractInfo,
} from "../clients/ai-client";
import { createEtherscanClient } from "../clients/etherscan-client";
import { config, validateConfig } from "../config/env";
import { createDefaultProxy } from "../domain/vulnerability";
import type {
  DatasetRecord,
  ResolutionStatus,
  ResolvedContract,
} from "../domain/vulnerability";
import { FileCache } from "../lib/cache";
import { MinIntervalGate, runWithConcurrency, Semaphore } from "../lib/concurrency";
import { createLogger } from "../lib/logger";
import {
  createContractFetcher,
  type ContractFetcher,
} from "../services/contract-fetcher";
import {
  computeIdempotencyKey,
  createDatasetWriter,
  type ProgressSnapshotStats,
  type DatasetWriter,
} from "../services/dataset-writer";
import { createPOCParser } from "../services/poc-parser";
import { createTargetResolver } from "../services/target-resolver";

const logger = createLogger("info");

interface PipelineContext {
  parser: ReturnType<typeof createPOCParser>;
  resolver: ReturnType<typeof createTargetResolver>;
  fetcher: ContractFetcher;
  writer: DatasetWriter;
  aiClient: AIClient;
  etherscanClient: ReturnType<typeof createEtherscanClient>;
  foundryChains: ChainContext[];
}

type ProcessOutcome =
  | {
      kind: "success";
      id: string;
      record: DatasetRecord;
      status: ResolutionStatus;
      durationMs: number;
    }
  | {
      kind: "failed";
      id: string;
      reason: string;
      durationMs: number;
    }
  | {
      kind: "skipped";
      id: string;
      reason: string;
      durationMs: number;
    };

interface AIExecutionLimits {
  extractionSemaphore: Semaphore;
  analysisSemaphore: Semaphore;
  extractionDelayGate: MinIntervalGate;
  analysisDelayGate: MinIntervalGate;
}

function hasRequiredAIAnalysis(record: DatasetRecord | undefined): boolean {
  if (!record) return false;
  if (!config.ai_enabled) return true;
  if (!record.ai_analysis) return false;
  if (config.ai_enable_mitigation) {
    return Array.isArray(record.ai_analysis.mitigation);
  }
  return true;
}

async function loadExistingDatasetRecords(
  outputDir: string,
): Promise<DatasetRecord[]> {
  try {
    const raw = await readFile(join(outputDir, "dataset.json"), "utf-8");
    const parsed = JSON.parse(raw) as unknown;

    if (Array.isArray(parsed)) {
      return parsed as DatasetRecord[];
    }

    if (
      parsed &&
      typeof parsed === "object" &&
      Array.isArray((parsed as { records?: unknown[] }).records)
    ) {
      return (parsed as { records: DatasetRecord[] }).records;
    }
  } catch {
    // No previous dataset available.
  }

  return [];
}

class PipelineProgress {
  private readonly startedAt = Date.now();
  private readonly total: number;
  private readonly workerConcurrency: number;
  private readonly useBar: boolean;
  private bar: cliProgress.SingleBar | null = null;
  private inFlight = 0;
  private completed = 0;
  private success = 0;
  private failed = 0;
  private skipped = 0;
  private analyzed = 0;
  private lastLogAt = 0;

  constructor(total: number, workerConcurrency: number) {
    this.total = total;
    this.workerConcurrency = workerConcurrency;
    this.useBar = Boolean(process.stdout.isTTY);
  }

  start() {
    if (!this.useBar) {
      this.lastLogAt = Date.now();
      logger.info(
        `Progress tracking: ${this.total} items (non-interactive mode, summary logs only)`,
      );
      return;
    }

    this.bar = new cliProgress.SingleBar(
      {
        clearOnComplete: true,
        hideCursor: true,
        etaBuffer: 30,
        format:
          "Progress |{bar}| {percentage}% {value}/{total} | ok:{ok} analyzed:{analyzed} fail:{failed} skip:{skipped} in_flight:{inFlight}/{workers} rate:{rate}/s ETA:{eta}s",
      },
      cliProgress.Presets.shades_classic,
    );

    this.bar.start(this.total, 0, {
      ok: 0,
      analyzed: 0,
      failed: 0,
      skipped: 0,
      inFlight: 0,
      workers: this.workerConcurrency,
      rate: "0.00",
    });
  }

  stop() {
    if (this.bar) {
      this.bar.stop();
      this.bar = null;
    }
    if (this.completed !== this.total) {
      this.logSnapshot(true);
    }
  }

  onItemStart() {
    this.inFlight++;
    this.logSnapshot(false);
  }

  onItemDone(outcome: ProcessOutcome) {
    this.inFlight = Math.max(0, this.inFlight - 1);
    this.completed++;

    if (outcome.kind === "success") {
      this.success++;
      if (outcome.record.ai_analysis) {
        this.analyzed++;
      }
    } else if (outcome.kind === "failed") {
      this.failed++;
    } else {
      this.skipped++;
    }

    this.logSnapshot(this.completed === this.total);
  }

  private logSnapshot(force: boolean) {
    const now = Date.now();
    if (!this.bar && !force && now - this.lastLogAt < 30000) return;

    const elapsedSec = Math.max(1, Math.floor((now - this.startedAt) / 1000));
    const processed = this.completed;
    const rate = processed / elapsedSec;
    const remaining = Math.max(0, this.total - processed);
    const etaSec = rate > 0 ? Math.ceil(remaining / rate) : 0;

    if (this.bar) {
      this.bar.update(processed, {
        ok: this.success,
        analyzed: this.analyzed,
        failed: this.failed,
        skipped: this.skipped,
        inFlight: this.inFlight,
        workers: this.workerConcurrency,
        rate: rate.toFixed(2),
      });
      return;
    }

    this.lastLogAt = now;
    logger.info(`Progress ${processed}/${this.total} | ok=${this.success} analyzed=${this.analyzed} failed=${this.failed} skipped=${this.skipped} in_flight=${this.inFlight}/${this.workerConcurrency} rate=${rate.toFixed(2)}/s eta=${etaSec}s`);
  }
}

async function loadFoundryChains(inputDir: string): Promise<ChainContext[]> {
  try {
    const foundryPath = inputDir.replace("/src/test", "/foundry.toml");
    const content = await readFile(foundryPath, "utf-8");
    return parseFoundryChains(content);
  } catch {
    logger.warn("No foundry.toml found");
    return [];
  }
}

async function initializePipeline(): Promise<PipelineContext> {
  logger.info("Initializing pipeline...");

  const validation = validateConfig();
  if (!validation.valid) {
    logger.error("Invalid config", validation.errors.join(", "));
    process.exit(1);
  }

  const foundryChains = await loadFoundryChains(config.input_dir);
  logger.info(`Loaded ${foundryChains.length} chains from foundry.toml`);

  const parser = createPOCParser();
  const resolver = createTargetResolver();

  const cache = new FileCache({
    cacheDir: `${config.cache_dir}/contracts`,
    ttlSeconds: config.cache_ttl_seconds,
  });

  const etherscanClient = createEtherscanClient(
    config.etherscan_api_key,
    config.etherscan_tier,
    config.rate_limit_rps,
  );
  const fetcher = createContractFetcher({
    etherscanClient,
    cache,
    config,
  });
  const aiClient = createAIClient();

  const writer = createDatasetWriter({
    output_dir: config.output_dir,
    contracts_dir: config.contracts_dir,
    chunk_size: config.chunk_size,
    idempotency_dir: config.idempotency_dir,
    ai_enable_mitigation: config.ai_enable_mitigation,
  });

  await writer.initialize();

  logger.info(`Etherscan tier: ${config.etherscan_tier}`);
  logger.info(`Contracts output directory: ${config.contracts_dir}`);
  logger.info(
    `Parallelism: workers=${Math.max(1, config.pipeline_parallel)}, fetch_parallel=${Math.max(1, config.fetch_parallel)}, ai_parallel=${Math.max(1, config.ai_parallel)}`,
  );
  if (aiClient.isEnabled()) {
    const sharedAIQueue =
      aiClient.getExtractionProvider() === aiClient.getAnalysisProvider();
    logger.info(
      `AI enabled: extraction=${aiClient.getExtractionModel()}, analysis=${aiClient.getAnalysisModel()}, min_request_gap=${Math.max(0, config.ai_delay_ms)}ms`,
    );
    logger.info(
      `AI scheduling: ${sharedAIQueue ? "shared provider queue" : "separate extraction/analysis queues"}`,
    );
    logger.info(
      `AI mitigation processing: ${config.ai_enable_mitigation ? "enabled" : "disabled"}`,
    );
  }

  return {
    parser,
    resolver,
    fetcher,
    writer,
    aiClient,
    etherscanClient,
    foundryChains,
  };
}

function buildEvidence(
  contracts: DatasetRecord["contracts"],
): DatasetRecord["resolution"]["evidence"] {
  return contracts.map((contract) => {
    if (contract.is_verified) {
      return `verified: ${contract.address}`;
    }
    if (contract.fetch_error) {
      return `failed: ${contract.address} (${contract.fetch_error})`;
    }
    return `unverified: ${contract.address}`;
  });
}

function buildUnsupportedContract(
  target: {
    address: string;
    role: "vulnerable" | "attacker" | "helper" | "unknown";
    chain_id: number;
    chain_name: string;
    source_hint: string;
  },
): ResolvedContract {
  return {
    address: target.address.toLowerCase(),
    role: target.role,
    source_hint: target.source_hint,
    chain_id: target.chain_id,
    chain_name: target.chain_name,
    is_verified: false,
    verification_status: "not_found",
    proxy: createDefaultProxy(),
    explorer_url: "",
    fetched_at: new Date().toISOString(),
    fetch_error: "etherscan_unavailable_freetier",
  };
}

async function processPOCFile(
  ctx: PipelineContext,
  filePath: string,
  aiLimits: AIExecutionLimits,
  existingRecordsById: Map<string, DatasetRecord>,
): Promise<ProcessOutcome> {
  const start = Date.now();
  let id = filePath;

  try {
    const parsed = await ctx.parser.parsePOCFile(filePath);
    id = parsed.id;

    const idempotencyKey = computeIdempotencyKey(
      parsed.code,
      ctx.parser.getVersion(),
      config,
    );
    const alreadyProcessed = await ctx.writer.hasIdempotencyKey(idempotencyKey);
    if (alreadyProcessed && config.idempotency_strategy === "skip") {
      const existingRecord = existingRecordsById.get(id);
      if (hasRequiredAIAnalysis(existingRecord)) {
        return {
          kind: "skipped",
          id,
          reason: "idempotent_skip",
          durationMs: Date.now() - start,
        };
      }
    }

    let aiExtraction: ExtractedContractInfo | null = null;
    let extractionFailed = false;
    if (ctx.aiClient.isEnabled()) {
      aiExtraction = await aiLimits.extractionSemaphore.use(async () => {
        await aiLimits.extractionDelayGate.waitTurn();
        return await ctx.aiClient.extractContractInfo(parsed, ctx.foundryChains);
      });

      if (!aiExtraction?.vulnerable_contracts?.length) {
        extractionFailed = true;
        aiExtraction = null;
      }
    }

    const resolved = ctx.resolver.resolveTargets(
      parsed,
      aiExtraction?.vulnerable_contracts ?? null,
    );

    const unsupportedTargets = resolved.contracts.filter(
      (contract) => !ctx.etherscanClient.isChainSupported(contract.chain_id),
    );
    const supportedTargets = resolved.contracts.filter((contract) =>
      ctx.etherscanClient.isChainSupported(contract.chain_id),
    );

    const fetchedContracts = await ctx.fetcher.fetchContracts(supportedTargets);
    const unsupportedContracts = unsupportedTargets.map((target) =>
      buildUnsupportedContract(target),
    );
    const contracts = [...fetchedContracts, ...unsupportedContracts];

    let status = ctx.fetcher.determineResolutionStatus(contracts);
    const evidence = buildEvidence(contracts);

    if (unsupportedTargets.length > 0) {
      status = "chain_unsupported";
      const unsupportedChains = [...new Set(unsupportedTargets.map((c) => c.chain_id))];
      evidence.unshift(
        `unsupported_chains: ${unsupportedChains.join(",")} (tier=${config.etherscan_tier})`,
      );
    }

    if (extractionFailed && resolved.contracts.length === 0) {
      status = "parse_failed";
      evidence.unshift("ai_extraction_failed: empty or invalid output");
    }

    let aiAnalysis: DatasetRecord["ai_analysis"] | undefined;
    const canRunAnalysis = ctx.aiClient.isEnabled() && contracts.length > 0;
    if (canRunAnalysis) {
      aiAnalysis = await aiLimits.analysisSemaphore.use(async () => {
        await aiLimits.analysisDelayGate.waitTurn();
        return await ctx.aiClient.analyzeExploit(
          parsed,
          contracts,
          aiExtraction,
          ctx.foundryChains,
        );
      }) ?? undefined;
    }

    const aiModelTag = ctx.aiClient.isEnabled()
      ? `${ctx.aiClient.getExtractionModel()}|${ctx.aiClient.getAnalysisModel()}`
      : undefined;

    const record: DatasetRecord = {
      id,
      title: parsed.title,
      attack_title: parsed.attack_title,
      testcase: parsed.code,
      resolution: {
        status,
        evidence,
        resolved_at: new Date().toISOString(),
      },
      contracts,
      ai_analysis: aiAnalysis,
      metadata: {
        poc_parser_version: ctx.parser.getVersion(),
        dataset_version: "1.0.0",
        processed_at: new Date().toISOString(),
        ai_enabled: config.ai_enabled,
        ai_model: aiModelTag,
      },
    };

    await ctx.writer.writeIdempotencyKey(idempotencyKey, {
      id,
      processed_at: new Date().toISOString(),
    });

    return {
      kind: "success",
      id,
      record,
      status,
      durationMs: Date.now() - start,
    };
  } catch (error) {
    return {
      kind: "failed",
      id,
      reason: String(error),
      durationMs: Date.now() - start,
    };
  }
}

function createAILimits(ctx: PipelineContext): AIExecutionLimits {
  const aiConcurrency = Math.max(1, config.ai_parallel);
  const delayMs = Math.max(0, config.ai_delay_ms);

  const extractionSemaphore = new Semaphore(aiConcurrency);
  const extractionDelayGate = new MinIntervalGate(delayMs);

  const sameProvider =
    ctx.aiClient.getExtractionProvider() === ctx.aiClient.getAnalysisProvider();

  if (sameProvider) {
    return {
      extractionSemaphore,
      analysisSemaphore: extractionSemaphore,
      extractionDelayGate,
      analysisDelayGate: extractionDelayGate,
    };
  }

  return {
    extractionSemaphore,
    analysisSemaphore: new Semaphore(aiConcurrency),
    extractionDelayGate,
    analysisDelayGate: new MinIntervalGate(delayMs),
  };
}

async function runPipeline() {
  logger.info("=".repeat(60));
  logger.info("DeFi Vulnerability Dataset Pipeline");
  logger.info("=".repeat(60));

  const ctx = await initializePipeline();
  const pocFiles = await ctx.parser.findPOCFiles(config.input_dir);
  const filesToProcess = config.test_limit
    ? pocFiles.slice(0, config.test_limit)
    : pocFiles;

  logger.info(
    `Found ${pocFiles.length} POCs, processing ${filesToProcess.length}`,
  );

  if (filesToProcess.length === 0) {
    logger.info("No files to process");
    return;
  }

  const workerConcurrency = Math.max(1, config.pipeline_parallel);
  const aiLimits = createAILimits(ctx);
  const existingRecords = await loadExistingDatasetRecords(config.output_dir);
  const existingRecordsById = new Map(
    existingRecords.map((record) => [record.id, record] as const),
  );
  const liveRecordsById = new Map<string, DatasetRecord>();
  if (config.idempotency_strategy === "skip") {
    for (const record of existingRecords) {
      liveRecordsById.set(record.id, record);
    }
  }
  const liveFailedIds = new Set<string>();
  let liveProcessed = 0;
  let liveSuccess = 0;
  let liveFailed = 0;
  let liveSkipped = 0;
  let liveAnalyzed = Array.from(liveRecordsById.values()).filter(
    (record) => record.ai_analysis,
  ).length;
  let pendingSinceSnapshot = 0;
  let lastSnapshotAt = Date.now();
  let checkpointRunning = false;
  let checkpointQueued = false;
  const checkpointEvery = Math.max(1, config.chunk_size);
  const snapshotIntervalMs = 15000;

  const snapshotStats = (): ProgressSnapshotStats => ({
    total: filesToProcess.length,
    processed: liveProcessed,
    success: liveSuccess,
    failed: liveFailed,
    skipped: liveSkipped,
    analyzed: liveAnalyzed,
  });

  const writeSnapshot = async (force: boolean) => {
    const now = Date.now();
    if (!force) {
      const dueByCount = pendingSinceSnapshot >= checkpointEvery;
      const dueByTime = now - lastSnapshotAt >= snapshotIntervalMs;
      if (!dueByCount && !dueByTime) {
        return;
      }
    }
    if (checkpointRunning) {
      checkpointQueued = true;
      return;
    }

    checkpointRunning = true;
    do {
      checkpointQueued = false;
      await ctx.writer.writeProgressSnapshot(
        Array.from(liveRecordsById.values()),
        Array.from(liveFailedIds),
        snapshotStats(),
      );
      pendingSinceSnapshot = 0;
      lastSnapshotAt = Date.now();
    } while (checkpointQueued);
    checkpointRunning = false;
  };
  const progress = new PipelineProgress(filesToProcess.length, workerConcurrency);
  progress.start();

  const outcomes = await runWithConcurrency(
    filesToProcess,
    workerConcurrency,
    async (filePath) => {
      progress.onItemStart();
      const outcome = await processPOCFile(
        ctx,
        filePath,
        aiLimits,
        existingRecordsById,
      );
      liveProcessed++;
      pendingSinceSnapshot++;
      if (outcome.kind === "success") {
        liveSuccess++;
        liveRecordsById.set(outcome.record.id, outcome.record);
        if (outcome.record.ai_analysis) {
          liveAnalyzed++;
        }
      } else if (outcome.kind === "failed") {
        liveFailed++;
        liveFailedIds.add(outcome.id);
      } else {
        liveSkipped++;
      }
      await writeSnapshot(false);
      progress.onItemDone(outcome);

      return outcome;
    },
  );

  progress.stop();
  await writeSnapshot(true);

  const records: DatasetRecord[] = [];
  const failedIds = new Set<string>();
  const failureReasons = new Map<string, number>();

  for (const outcome of outcomes) {
    if (outcome.kind === "success") {
      records.push(outcome.record);
      continue;
    }
    if (outcome.kind === "failed") {
      failedIds.add(outcome.id);
      failureReasons.set(
        outcome.reason,
        (failureReasons.get(outcome.reason) ?? 0) + 1,
      );
    }
  }

  const skippedCount = outcomes.filter((o) => o.kind === "skipped").length;
  if (
    config.idempotency_strategy === "skip" &&
    records.length === 0 &&
    failedIds.size === 0 &&
    skippedCount === outcomes.length
  ) {
    logger.info(
      "All items were skipped by idempotency; preserving existing dataset output (no rewrite)",
    );
    logger.info("=".repeat(60));
    logger.info(
      `Done: ${records.length} new success, ${failedIds.size} failed, ${skippedCount} skipped, total_saved=unchanged`,
    );
    logger.info("=".repeat(60));
    return;
  }

  let finalRecords = records;
  if (config.idempotency_strategy === "skip") {
    if (existingRecords.length > 0) {
      const byId = new Map(existingRecords.map((record) => [record.id, record]));
      for (const record of records) {
        byId.set(record.id, record);
      }
      finalRecords = Array.from(byId.values());
      logger.info(
        `Merged ${records.length} new records with ${existingRecords.length} existing records (final=${finalRecords.length})`,
      );
    }
  }

  await ctx.writer.finalize(finalRecords, Array.from(failedIds));

  logger.info("=".repeat(60));
  logger.info(
    `Done: ${records.length} new success, ${failedIds.size} failed, ${skippedCount} skipped, total_saved=${finalRecords.length}`,
  );
  if (failureReasons.size > 0) {
    const topReasons = Array.from(failureReasons.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([reason, count]) => `${reason} (${count})`)
      .join(", ");
    logger.info(`Top failure reasons: ${topReasons}`);
  }
  logger.info("=".repeat(60));
}

runPipeline().catch((error) => {
  logger.error("Pipeline failed", String(error));
  process.exit(1);
});
