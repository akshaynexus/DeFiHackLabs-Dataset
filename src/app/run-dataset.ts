import { createPOCParser } from "../services/poc-parser";
import { createTargetResolver } from "../services/target-resolver";
import {
  createContractFetcher,
  type ContractFetcher,
} from "../services/contract-fetcher";
import {
  createDatasetWriter,
  computeIdempotencyKey,
  type DatasetWriter,
} from "../services/dataset-writer";
import { createEtherscanClient } from "../clients/etherscan-client";
import {
  createAIClient,
  parseFoundryChains,
  type ChainContext,
  type AIClient,
} from "../clients/ai-client";
import { createLogger } from "../lib/logger";
import { FileCache } from "../lib/cache";
import { config, validateConfig } from "../config/env";
import { readFile } from "fs/promises";
import type { DatasetRecord } from "../domain/vulnerability";

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
    cacheDir: config.cache_dir + "/contracts",
    ttlSeconds: config.cache_ttl_seconds,
  });

  const etherscanClient = createEtherscanClient(
    config.etherscan_api_key,
    config.etherscan_tier,
  );
  const fetcher = createContractFetcher({
    etherscanClient: etherscanClient as any,
    cache,
    config,
  });
  const aiClient = createAIClient();

  const writer = createDatasetWriter({
    outputDir: config.output_dir,
    chunkSize: config.chunk_size,
    idempotencyDir: config.idempotency_dir,
  });

  await writer.initialize();

  logger.info(`Etherscan tier: ${config.etherscan_tier}`);
  if (aiClient.isEnabled()) {
    logger.info(
      `AI enabled: extraction=${aiClient.getExtractionModel()}, analysis=${aiClient.getAnalysisModel()}`,
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

async function processPOC(
  ctx: PipelineContext,
  filePath: string,
): Promise<DatasetRecord | null> {
  const startTime = Date.now();

  try {
    // Step 1: Parse POC to get raw code
    const parsed = await ctx.parser.parsePOCFile(filePath);

    // Check idempotency
    const idempotencyKey = computeIdempotencyKey(
      parsed.code,
      ctx.parser.getVersion(),
      config,
    );
    const alreadyProcessed = await ctx.writer.hasIdempotencyKey(idempotencyKey);

    if (alreadyProcessed && config.idempotency_strategy === "skip") {
      logger.info(`Skipping ${parsed.id} (already processed)`);
      return null;
    }

    // Step 2: AI Extract - identify vulnerable contracts from POC code + foundry chains
    let aiExtraction: {
      vulnerable_contracts: Array<{
        address: string;
        role: "vulnerable" | "attacker" | "helper";
        chain_id: number;
        reason: string;
      }>;
      attack_summary: string;
      vulnerability_type: string;
      root_cause: string;
    } | null = null;

    if (ctx.aiClient.isEnabled()) {
      aiExtraction = await ctx.aiClient.extractContractInfo(
        parsed,
        ctx.foundryChains,
      );
      if (!aiExtraction || !aiExtraction.vulnerable_contracts || aiExtraction.vulnerable_contracts.length === 0) {
        logger.error(`AI extraction returned no contracts for ${parsed.id}`);
        await ctx.writer.markFailed(parsed.id, "AI extraction returned no contracts");
        return null;
      }
      logger.debug(
        `AI extracted: ${aiExtraction.vulnerable_contracts.length} contracts`,
      );
    }

    // Step 3: Resolve targets using AI extraction
    const resolved = ctx.resolver.resolveTargets(
      parsed,
      aiExtraction?.vulnerable_contracts ?? null,
    );

    // Skip unsupported chains for free tier
    const unsupportedChains = resolved.contracts
      .map((c) => c.chain_id)
      .filter((chainId) => !ctx.etherscanClient.isChainSupported(chainId));

    if (unsupportedChains.length > 0 && config.etherscan_tier === "free") {
      logger.info(
        `Skipping ${parsed.id} - unsupported chain: ${[...new Set(unsupportedChains)].join(", ")}`,
      );
      return null;
    }

    // Step 4: Fetch contract data from Etherscan
    const contracts = await ctx.fetcher.fetchContracts(resolved.contracts);
    const status = ctx.fetcher.determineResolutionStatus(contracts);

    // Build evidence
    const evidence: string[] = [];
    for (const c of contracts) {
      if (c.is_verified) evidence.push(`verified: ${c.address}`);
      else if (c.fetch_error)
        evidence.push(`failed: ${c.address} (${c.fetch_error})`);
      else evidence.push(`unverified: ${c.address}`);
    }

    // Step 5: AI Analyze with full context
    let aiAnalysis = null;
    if (ctx.aiClient.isEnabled() && status === "resolved") {
      aiAnalysis = await ctx.aiClient.analyzeExploit(
        parsed,
        contracts,
        aiExtraction,
        ctx.foundryChains,
      );
      if (!aiAnalysis) {
        logger.warn(`AI analysis failed for ${parsed.id}, continuing without it`);
      }
    }

    const record: DatasetRecord = {
      id: parsed.id,
      title: parsed.title,
      attack_title: parsed.attack_title,
      testcase: parsed.code,
      resolution: { status, evidence, resolved_at: new Date().toISOString() },
      contracts,
      ai_analysis: aiAnalysis ?? undefined,
      metadata: {
        poc_parser_version: ctx.parser.getVersion(),
        dataset_version: "1.0.0",
        processed_at: new Date().toISOString(),
        ai_enabled: config.ai_enabled,
        ai_model: config.ai_model,
      },
    };

    await ctx.writer.writeIdempotencyKey(idempotencyKey, {
      id: parsed.id,
      processed_at: new Date().toISOString(),
    });

    logger.info(
      `Processed ${parsed.id} in ${Date.now() - startTime}ms [${status}]`,
    );
    return record;
  } catch (error) {
    logger.error(`Failed to process ${filePath}: ${error}`);
    return null;
  }
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

  const results: DatasetRecord[] = [];
  const failed: string[] = [];

  // Phase 1: Parse + AI Extract (fast, sequential to not overload AI)
  const parsedResults: Array<{
    parsed: any;
    aiExtraction: any;
    idempotencyKey: string;
  }> = [];

  for (let i = 0; i < filesToProcess.length; i++) {
    try {
      const parsed = await ctx.parser.parsePOCFile(filesToProcess[i]);
      
      const idempotencyKey = computeIdempotencyKey(
        parsed.code,
        ctx.parser.getVersion(),
        config,
      );
      const alreadyProcessed = await ctx.writer.hasIdempotencyKey(idempotencyKey);
      
      if (alreadyProcessed && config.idempotency_strategy === "skip") {
        logger.info(`Skipping ${parsed.id} (already processed)`);
        continue;
      }

      let aiExtraction = null;
      if (ctx.aiClient.isEnabled()) {
        aiExtraction = await ctx.aiClient.extractContractInfo(parsed, ctx.foundryChains);
        if (!aiExtraction?.vulnerable_contracts?.length) {
          logger.error(`AI extraction failed for ${parsed.id}`);
          failed.push(parsed.id);
          continue;
        }
      }

      parsedResults.push({ parsed, aiExtraction, idempotencyKey });
      
      if ((i + 1) % 10 === 0) {
        logger.info(`Phase 1 Progress: ${i + 1}/${filesToProcess.length} parsed`);
      }
    } catch (error) {
      logger.error(`Failed to parse ${filesToProcess[i]}: ${error}`);
    }
  }

  logger.info(`Phase 1 complete: ${parsedResults.length} ready for fetching`);

  // Phase 2: Fetch contracts + AI Analyze (parallel)
  for (let i = 0; i < parsedResults.length; i++) {
    const { parsed, aiExtraction, idempotencyKey } = parsedResults[i];
    
    try {
      const resolved = ctx.resolver.resolveTargets(parsed, aiExtraction?.vulnerable_contracts ?? null);
      
      const unsupportedChains = resolved.contracts
        .map((c: any) => c.chain_id)
        .filter((chainId: number) => !ctx.etherscanClient.isChainSupported(chainId));
      
      if (unsupportedChains.length > 0 && config.etherscan_tier === "free") {
        logger.info(`Skipping ${parsed.id} - unsupported chain`);
        failed.push(parsed.id);
        continue;
      }

      const contracts = await ctx.fetcher.fetchContracts(resolved.contracts);
      const status = ctx.fetcher.determineResolutionStatus(contracts);

      const evidence: string[] = [];
      for (const c of contracts) {
        if (c.is_verified) evidence.push(`verified: ${c.address}`);
        else if (c.fetch_error) evidence.push(`failed: ${c.address} (${c.fetch_error})`);
        else evidence.push(`unverified: ${c.address}`);
      }

      // AI Analyze (if resolved)
      let aiAnalysis = null;
      if (ctx.aiClient.isEnabled() && status === "resolved") {
        aiAnalysis = await ctx.aiClient.analyzeExploit(parsed, contracts, aiExtraction, ctx.foundryChains);
      }

      const record: DatasetRecord = {
        id: parsed.id,
        title: parsed.title,
        attack_title: parsed.attack_title,
        testcase: parsed.code,
        resolution: { status, evidence, resolved_at: new Date().toISOString() },
        contracts,
        ai_analysis: aiAnalysis ?? undefined,
        metadata: {
          poc_parser_version: ctx.parser.getVersion(),
          dataset_version: "1.0.0",
          processed_at: new Date().toISOString(),
          ai_enabled: config.ai_enabled,
          ai_model: config.ai_model,
        },
      };

      await ctx.writer.writeIdempotencyKey(idempotencyKey, { id: parsed.id, processed_at: new Date().toISOString() });
      results.push(record);
      
      if ((i + 1) % 10 === 0) {
        logger.info(`Phase 2 Progress: ${i + 1}/${parsedResults.length} fetched`);
      }
    } catch (error) {
      logger.error(`Failed to process ${parsed.id}: ${error}`);
      failed.push(parsed.id);
    }
  }

  await ctx.writer.finalize(results, failed);

  logger.info("=".repeat(60));
  logger.info(
    `Done: ${results.length} success, ${failed.length} failed`,
  );
  logger.info("=".repeat(60));
}

runPipeline().catch((error) => {
  logger.error("Pipeline failed", error);
  process.exit(1);
});
