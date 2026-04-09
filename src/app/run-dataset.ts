import { createPOCParser } from '../services/poc-parser';
import { createTargetResolver } from '../services/target-resolver';
import { createContractFetcher, type ContractFetcher } from '../services/contract-fetcher';
import { createDatasetWriter, computeIdempotencyKey, type DatasetWriter } from '../services/dataset-writer';
import { createEtherscanClient } from '../clients/etherscan-client';
import { createOpenRouterClient, type OpenRouterClient, parseFoundryChains, type ChainContext } from '../clients/openrouter-client';
import { createLogger } from '../lib/logger';
import { FileCache } from '../lib/cache';
import { config, validateConfig } from '../config/env';
import { getChainConfig } from '../domain/chain';
import { readFile } from 'fs/promises';
import type { DatasetRecord } from '../domain/vulnerability';

const logger = createLogger('info');

interface PipelineContext {
  parser: ReturnType<typeof createPOCParser>;
  resolver: ReturnType<typeof createTargetResolver>;
  fetcher: ContractFetcher;
  writer: DatasetWriter;
  aiClient: OpenRouterClient;
  etherscanClient: ReturnType<typeof createEtherscanClient>;
  foundryChains: ChainContext[];
}

async function loadFoundryChains(inputDir: string): Promise<ChainContext[]> {
  try {
    const foundryPath = inputDir.replace('/src/test', '/foundry.toml');
    const content = await readFile(foundryPath, 'utf-8');
    const chains = parseFoundryChains(content);
    logger.info(`Loaded ${chains.length} chains from foundry.toml`);
    return chains;
  } catch {
    logger.warn('No foundry.toml found, using default Ethereum');
    return [{
      chain_id: 1,
      chain_name: 'mainnet',
      rpc_url: '',
      source: 'default',
    }];
  }
}

async function initializePipeline(): Promise<PipelineContext> {
  logger.info('Initializing pipeline...');

  // Validate config
  const validation = validateConfig();
  if (!validation.valid) {
    logger.error('Invalid config', validation.errors.join(', '));
    process.exit(1);
  }

  // Load foundry chains
  const foundryChains = await loadFoundryChains(config.input_dir);

  // Initialize components
  const parser = createPOCParser();
  const resolver = createTargetResolver();
  
  const cache = new FileCache({
    cacheDir: config.cache_dir + '/contracts',
    ttlSeconds: config.cache_ttl_seconds,
  });

  const etherscanClient = createEtherscanClient(config.etherscan_api_key, config.etherscan_tier);
  const fetcher = createContractFetcher({
    etherscanClient: etherscanClient as any,
    cache,
    config,
  });

  const aiClient = createOpenRouterClient(config);

  const writer = createDatasetWriter({
    outputDir: config.output_dir,
    chunkSize: config.chunk_size,
    idempotencyDir: config.idempotency_dir,
  });

  await writer.initialize();

  logger.info(`Etherscan tier: ${config.etherscan_tier}`);
  if (config.etherscan_tier === 'free') {
    logger.info('Free tier - skipping non-Ethereum mainnet chains');
  }

  if (aiClient.isEnabled()) {
    logger.info(`AI enabled. Extraction: ${aiClient.getCheapModel()}, Analysis: ${aiClient.getMainModel()}`);
  }

  logger.info('Pipeline initialized');

  return { parser, resolver, fetcher, writer, aiClient, etherscanClient, foundryChains };
}

async function processPOC(
  ctx: PipelineContext,
  filePath: string
): Promise<DatasetRecord | null> {
  const startTime = Date.now();

  try {
    // Step 1: Parse POC
    logger.debug(`Parsing ${filePath}`);
    const parsed = await ctx.parser.parsePOCFile(filePath);

    // Check idempotency
    const idempotencyKey = computeIdempotencyKey(parsed.code, ctx.parser.getVersion(), config);
    const alreadyProcessed = await ctx.writer.hasIdempotencyKey(idempotencyKey);
    
    if (alreadyProcessed && config.idempotency_strategy === 'skip') {
      logger.info(`Skipping ${parsed.id} (already processed)`);
      return null;
    }

    // Step 1.5: AI extraction with foundry chain context
    let aiExtraction: {
      vulnerable_contracts: Array<{
        address: string;
        role: 'vulnerable' | 'attacker' | 'helper';
        chain_id: number;
        reason: string;
      }>;
      attack_summary: string;
      vulnerability_type: string;
      root_cause: string;
    } | null = null;

    if (ctx.aiClient.isEnabled()) {
      logger.debug(`AI extracting contracts for ${parsed.id}`);
      aiExtraction = await ctx.aiClient.extractContractInfo(parsed, ctx.foundryChains);
      
      if (aiExtraction) {
        logger.debug(`AI extracted: ${aiExtraction.vulnerable_contracts.length} contracts, type: ${aiExtraction.vulnerability_type}`);
      }
    }

    // Step 2: Resolve targets (use AI extraction if available)
    const resolved = ctx.resolver.resolveTargets(parsed, aiExtraction?.vulnerable_contracts ?? null);

    // Skip POCs on unsupported chains for free tier
    const unsupportedChains = resolved.contracts
      .map(c => c.chain_id)
      .filter(chainId => !ctx.etherscanClient.isChainSupported(chainId));
    
    if (unsupportedChains.length > 0 && config.etherscan_tier === 'free') {
      logger.info(`Skipping ${parsed.id} - uses unsupported chains for free tier: ${[...new Set(unsupportedChains)].join(', ')}`);
      return null;
    }

    // Step 3: Fetch contracts
    const contracts = await ctx.fetcher.fetchContracts(resolved.contracts);

    // Step 4: Determine resolution status
    const status = ctx.fetcher.determineResolutionStatus(contracts);

    // Build evidence array
    const evidence: string[] = [];
    for (const c of contracts) {
      if (c.is_verified) {
        evidence.push(`verified: ${c.address}`);
      } else if (c.fetch_error) {
        evidence.push(`failed: ${c.address} (${c.fetch_error})`);
      } else {
        evidence.push(`unverified: ${c.address}`);
      }
    }

    // Step 5: AI analysis with foundry context, proxy info, and extraction context
    let aiAnalysis = null;
    if (ctx.aiClient.isEnabled() && status === 'resolved') {
      logger.debug(`AI analyzing ${parsed.id}`);
      aiAnalysis = await ctx.aiClient.analyzeExploit(
        parsed,
        contracts,
        aiExtraction ? {
          attack_summary: aiExtraction.attack_summary,
          vulnerability_type: aiExtraction.vulnerability_type,
          root_cause: aiExtraction.root_cause,
        } : null,
        ctx.foundryChains
      );
    }

    // Step 6: Build record
    const record: DatasetRecord = {
      id: parsed.id,
      title: parsed.title,
      attack_title: parsed.attack_title,
      testcase: parsed.code,
      resolution: {
        status,
        evidence,
        resolved_at: new Date().toISOString(),
      },
      contracts,
      ai_analysis: aiAnalysis ?? undefined,
      metadata: {
        poc_parser_version: ctx.parser.getVersion(),
        dataset_version: '1.0.0',
        processed_at: new Date().toISOString(),
        ai_enabled: config.ai_enabled,
        ai_model: config.ai_model,
      },
    };

    // Write idempotency key
    await ctx.writer.writeIdempotencyKey(idempotencyKey, {
      id: parsed.id,
      processed_at: new Date().toISOString(),
    });

    const duration = Date.now() - startTime;
    logger.info(`Processed ${parsed.id} in ${duration}ms [${status}]`);

    return record;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error(`Failed to process ${filePath}: ${message}`);
    return null;
  }
}

async function runPipeline() {
  logger.info('='.repeat(60));
  logger.info('Starting DeFi Vulnerability Dataset Pipeline');
  logger.info('='.repeat(60));

  const ctx = await initializePipeline();

  // Find POC files
  const pocFiles = await ctx.parser.findPOCFiles(config.input_dir);
  logger.info(`Found ${pocFiles.length} POC files`);

  // Apply test limit if set
  const filesToProcess = config.test_limit 
    ? pocFiles.slice(0, config.test_limit)
    : pocFiles;

  logger.info(`Processing ${filesToProcess.length} files (limit: ${config.test_limit ?? 'none'})`);

  // Process files
  let successCount = 0;
  let skipCount = 0;
  let unsupportedCount = 0;

  for (let i = 0; i < filesToProcess.length; i++) {
    const filePath = filesToProcess[i];
    
    logger.info(`[${i + 1}/${filesToProcess.length}] Processing ${filePath}`);
    
    const record = await processPOC(ctx, filePath);
    
    if (record) {
      await ctx.writer.writeRecord(record);
      successCount++;
    } else {
      skipCount++;
      // Check if it was skipped due to unsupported chain
      const parsed = await ctx.parser.parsePOCFile(filePath);
      const resolved = ctx.resolver.resolveTargets(parsed);
      const unsupported = resolved.contracts
        .map(c => c.chain_id)
        .filter(chainId => !ctx.etherscanClient.isChainSupported(chainId));
      if (unsupported.length > 0) {
        unsupportedCount++;
      }
    }
  }

  // Finalize
  await ctx.writer.finalize();

  const manifest = ctx.writer.getManifest();

  logger.info('='.repeat(60));
  logger.info('Pipeline Complete');
  logger.info(`Total: ${filesToProcess.length}`);
  logger.info(`Success: ${successCount}`);
  logger.info(`Skipped (already processed): ${skipCount - unsupportedCount}`);
  logger.info(`Skipped (unsupported chain): ${unsupportedCount}`);
  logger.info(`Failed: ${manifest.failed_ids.length}`);
  logger.info(`Batches: ${manifest.total_batches}`);
  logger.info('='.repeat(60));
}

// Run the pipeline
runPipeline().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  logger.error('Pipeline failed', message);
  process.exit(1);
});
