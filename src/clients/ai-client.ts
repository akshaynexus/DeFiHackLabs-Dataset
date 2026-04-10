import { createOpenAI } from "@ai-sdk/openai";
import { generateText } from "ai";

import { config, extraction, analysis } from "../config/env";
import { logger } from "../lib/logger";
import { asyncRetry } from "../lib/retry";
import type {
  AnalysisOutput,
  ParsedPOC,
  ResolvedContract,
} from "../domain/vulnerability";

const RPC_TO_CHAIN: Record<string, number> = {
  mainnet: 1,
  ethereum: 1,
  sepolia: 11155111,
  goerli: 5,
  bsc: 56,
  binance: 56,
  polygon: 137,
  matic: 137,
  arbitrum: 42161,
  optimism: 10,
  op: 10,
  avalanche: 43114,
  avax: 43114,
  base: 8453,
  linea: 59144,
  blast: 81457,
  gnosis: 100,
  celo: 42220,
  mantle: 5000,
  fantom: 250,
  sei: 1328,
  scroll: 534352,
  taiko: 167000,
};

export interface ChainContext {
  chain_id: number;
  chain_name: string;
  rpc_url: string;
  source: "foundry" | "explorer" | "ai";
}

export interface ExtractedContractInfo {
  vulnerable_contracts: Array<{
    address: string;
    role: "vulnerable" | "attacker" | "helper";
    chain_id: number;
    reason: string;
  }>;
  attack_summary: string;
  vulnerability_type: string;
  root_cause: string;
}

function createOpenAIClient(baseURL: string, apiKey: string) {
  return createOpenAI({
    baseURL,
    apiKey,
    headers: {
      "HTTP-Referer": "https://defihacklabs-dataset.local",
      "X-Title": "DeFi Vulnerability Dataset Generator",
    },
  });
}

function getAPIKeyForProvider(provider: string): string {
  const openrouterKey = process.env.OPENROUTER_API_KEY || "";
  const crofKey = process.env.CROF_API_KEY || "";
  const geminiKey = process.env.GEMINI_API_KEY || "";

  switch (provider) {
    case "crof":
      return crofKey;
    case "google":
      return geminiKey;
    default:
      return openrouterKey;
  }
}

export function parseFoundryChains(foundryContent: string): ChainContext[] {
  const chains: ChainContext[] = [];
  const lines = foundryContent.split("\n");

  let inRpcSection = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (trimmed === "[rpc_endpoints]") {
      inRpcSection = true;
      continue;
    }

    if (inRpcSection && trimmed.startsWith("[")) {
      inRpcSection = false;
      continue;
    }

    if (!inRpcSection || !trimmed.includes("=")) {
      continue;
    }

    const [rawName, rawUrl] = trimmed.split("=").map((part) => part.trim());

    if (!rawName || !rawUrl) {
      continue;
    }

    const chainId = RPC_TO_CHAIN[rawName.toLowerCase()];
    if (!chainId) {
      continue;
    }

    chains.push({
      chain_id: chainId,
      chain_name: rawName,
      rpc_url: rawUrl.replace(/"/g, ""),
      source: "foundry",
    });
  }

  return chains;
}

const AI_RETRY_ATTEMPTS = 3;
const AI_RETRY_INITIAL_DELAY_MS = 1200;
const AI_RETRY_MAX_DELAY_MS = 12000;

export class AIClient {
  private extractionClient: ReturnType<typeof createOpenAI> | null = null;
  private analysisClient: ReturnType<typeof createOpenAI> | null = null;
  private extractionModel = "";
  private analysisModel = "";
  private extractionProvider = "";
  private analysisProvider = "";
  private mitigationEnabled = true;
  private temperature = 0;
  private enabled = false;

  constructor() {
    if (!config.ai_enabled || !config.ai_api_key) {
      logger.info("AI client disabled");
      return;
    }

    this.enabled = true;
    this.extractionModel = config.ai_extraction_model;
    this.analysisModel = config.ai_analysis_model;
    this.extractionProvider = extraction.provider;
    this.analysisProvider = analysis.provider;
    this.mitigationEnabled = config.ai_enable_mitigation;

    // Create extraction client
    const extractionKey = getAPIKeyForProvider(this.extractionProvider);
    this.extractionClient = createOpenAIClient(extraction.base_url, extractionKey);

    // Create analysis client (may have different provider)
    const analysisKey = getAPIKeyForProvider(this.analysisProvider);
    this.analysisClient = createOpenAIClient(analysis.base_url, analysisKey);

    this.temperature = config.ai_temperature;

    logger.info(`AI client enabled`);
    logger.info(`  Extraction: ${this.extractionModel} (${this.extractionProvider}) @ ${extraction.base_url}`);
    logger.info(`  Analysis: ${this.analysisModel} (${this.analysisProvider}) @ ${analysis.base_url}`);
    logger.info(`  Mitigation generation: ${this.mitigationEnabled ? "enabled" : "disabled"}`);
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  getExtractionModel(): string {
    return this.extractionModel;
  }

  getAnalysisModel(): string {
    return this.analysisModel;
  }

  getExtractionProvider(): string {
    return this.extractionProvider;
  }

  getAnalysisProvider(): string {
    return this.analysisProvider;
  }

  isMitigationEnabled(): boolean {
    return this.mitigationEnabled;
  }

  async extractContractInfo(
    poc: ParsedPOC,
    foundryChains: ChainContext[],
  ): Promise<ExtractedContractInfo | null> {
    if (!this.enabled || !this.extractionClient) {
      return null;
    }

    try {
      return await this.withRetry("extraction", poc.id, async () => {
        return await this.extractContractInfoOnce(poc, foundryChains);
      });
    } catch (error) {
      const fallback = this.fallbackExtractContractInfo(poc, foundryChains);
      if (fallback) {
        logger.debug(
          `AI extraction fallback used for ${poc.id}: ${String(error)}`,
        );
        return fallback;
      }
      logger.debug(`AI extraction failed for ${poc.id}: ${String(error)}`);
      return null;
    }
  }

  async analyzeExploit(
    poc: ParsedPOC,
    contracts: ResolvedContract[],
    aiExtraction: Pick<
      ExtractedContractInfo,
      "attack_summary" | "vulnerability_type" | "root_cause"
    > | null,
    foundryChains: ChainContext[],
  ): Promise<AnalysisOutput | null> {
    if (!this.enabled || !this.analysisClient) {
      return null;
    }

    try {
      return await this.withRetry("analysis", poc.id, async () => {
        return await this.analyzeExploitOnce(
          poc,
          contracts,
          aiExtraction,
          foundryChains,
        );
      });
    } catch (error) {
      logger.warn(`AI analysis failed for ${poc.id}: ${String(error)}`);
      return null;
    }
  }

  private async extractContractInfoOnce(
    poc: ParsedPOC,
    foundryChains: ChainContext[],
  ): Promise<ExtractedContractInfo | null> {
    if (!this.extractionClient) {
      return null;
    }

    const chainsJson = JSON.stringify(
      foundryChains.map((chain) => ({
        chain_id: chain.chain_id,
        chain_name: chain.chain_name,
      })),
    );
    const isGemini = this.extractionProvider === "google";

    if (isGemini) {
      const result = await generateText({
        model: this.extractionClient(this.extractionModel),
        messages: [
          {
            role: "system",
            content: `You are a smart contract security analyzer. Read the POC code and extract contract info.

Output ONLY minified JSON (no whitespace, no markdown):
{"vulnerable_contracts":[{"address":"0x...","role":"vulnerable|attacker|helper","chain_id":1,"reason":"..."}],"attack_summary":"...","vulnerability_type":"...","root_cause":"..."}

- role: "vulnerable" = exploited protocol contract
- role: "attacker" = attack contract
- role: "helper" = token/interface/support contract
- chain_id: mainnet=1, bsc=56, polygon=137, arbitrum=42161, base=8453, optimism=10, avax=43114, linea=59144, blast=81457, gnosis=100`,
          },
          {
            role: "user",
            content: `Analyze this POC:

Title: ${poc.title}
Attack Title: ${poc.attack_title}

Available chains from foundry.toml:
${chainsJson}

Full POC Code:
${poc.code}`,
          },
        ],
        temperature: this.temperature,
        maxTokens: 16000,
      });

      const parsed = this.parseJsonPayload<unknown>(result.text);
      const normalized = parsed
        ? this.normalizeExtractedContractInfo(parsed)
        : null;

      if (!normalized) {
        throw new Error("invalid_extraction_json");
      }

      return normalized;
    }

    const result = await generateText({
      model: this.extractionClient(this.extractionModel),
      messages: [
        {
          role: "system",
          content: `You are a smart contract security analyzer. Read the POC code and extract contract info.

Output ONLY minified JSON (no whitespace, no markdown):
{"vulnerable_contracts":[{"address":"0x...","role":"vulnerable|attacker|helper","chain_id":1,"reason":"..."}],"attack_summary":"...","vulnerability_type":"...","root_cause":"..."}

- role: "vulnerable" = exploited protocol contract
- role: "attacker" = attack contract
- role: "helper" = token/interface/support contract
- chain_id: mainnet=1, bsc=56, polygon=137, arbitrum=42161, base=8453, optimism=10, avax=43114, linea=59144, blast=81457, gnosis=100`,
        },
        {
          role: "user",
          content: `Analyze this POC:

Title: ${poc.title}
Attack Title: ${poc.attack_title}

Available chains from foundry.toml:
${chainsJson}

Full POC Code:
${poc.code}`,
        },
      ],
      temperature: this.temperature,
      maxTokens: 16000,
    });

    const parsed = this.parseJsonPayload<unknown>(result.text);
    const normalized = parsed
      ? this.normalizeExtractedContractInfo(parsed)
      : null;
    if (!normalized) {
      throw new Error("invalid_extraction_json");
    }

    return normalized;
  }

  private async analyzeExploitOnce(
    poc: ParsedPOC,
    contracts: ResolvedContract[],
    aiExtraction: Pick<
      ExtractedContractInfo,
      "attack_summary" | "vulnerability_type" | "root_cause"
    > | null,
    foundryChains: ChainContext[],
  ): Promise<AnalysisOutput | null> {
    if (!this.analysisClient) {
      return null;
    }

    const contractsContext = contracts
      .map((contract) => {
        const verified = contract.is_verified ? "✓" : "✗";
        const proxy = contract.proxy.is_proxy
          ? ` (PROXY→${contract.proxy.implementation_address})`
          : "";
        const name = contract.contract_name ? ` [${contract.contract_name}]` : "";

        return `- ${contract.address}${name} (${contract.role}, chain${contract.chain_id}, ${verified})${proxy}`;
      })
      .join("\n");

    const contractsWithSource = contracts.filter(
      (contract) =>
        typeof contract.source_code === "string" &&
        contract.source_code.trim().length > 0,
    );

    const contractsWithBytecodeOnly = contracts.filter(
      (contract) =>
        (!contract.source_code || contract.source_code.trim().length === 0) &&
        typeof contract.bytecode === "string" &&
        contract.bytecode.trim().length > 0,
    );

    const sourceEntries = contractsWithSource.map(
      (contract) =>
        `=== ${contract.contract_name || contract.address} (source) ===\n${this.combineAndMinifySourceForAI(contract.source_code) || "No verified source code"}`,
    );
    const bytecodeEntries = contractsWithBytecodeOnly.map(
      (contract) =>
        `=== ${contract.contract_name || contract.address} (bytecode) ===\n${this.minifyBytecodeForAI(contract.bytecode || "")}`,
    );

    const sourceCodeContext =
      sourceEntries.length > 0 || bytecodeEntries.length > 0
        ? [...sourceEntries, ...bytecodeEntries].join("\n\n")
        : "No verified source code or bytecode";

    const proxyContracts = contracts.filter((contract) => contract.proxy.is_proxy);

    const proxyContext =
      proxyContracts.length > 0
        ? `\nProxy Contracts:\n${proxyContracts
            .map(
              (contract) =>
                `- ${contract.address} → ${contract.proxy.implementation_address}`,
            )
            .join("\n")}`
        : "";

    const chainsContext =
      foundryChains.length > 0
        ? `Chains: ${foundryChains.map((chain) => chain.chain_name).join(", ")}`
        : "No chain info";

    const result = await generateText({
      model: this.analysisClient(this.analysisModel),
      messages: [
        {
          role: "system",
          content: `You are a smart contract security analyst. Analyze DeFi exploits with full context.

Output ONLY minified JSON (no whitespace, no markdown):
${this.mitigationEnabled
  ? `{"explanation":"...","root_cause":"...","attack_steps":["...",...],"vulnerability_type":"...","mitigation":["...",...],"confidence":{"score":0.0,"factors":{"verified_contracts":true,"has_source_code":true,"known_pattern_match":true},"reasoning":"..."}}`
  : `{"explanation":"...","root_cause":"...","attack_steps":["...",...],"vulnerability_type":"...","confidence":{"score":0.0,"factors":{"verified_contracts":true,"has_source_code":true,"known_pattern_match":true},"reasoning":"..."}}`}`,
        },
        {
          role: "user",
          content: `Analyze: ${poc.title} / ${poc.attack_title}

AI Extraction: ${aiExtraction?.attack_summary ?? ""} | ${aiExtraction?.vulnerability_type ?? ""} | ${aiExtraction?.root_cause ?? ""}

${chainsContext}${proxyContext}

Contracts Found:
${contractsContext}

Verified Source Code:
${sourceCodeContext}

Full POC Code:
${poc.code}`,
        },
      ],
      temperature: this.temperature,
      maxTokens: 32000,
    });

    const parsed = this.parseJsonPayload<Partial<AnalysisOutput>>(result.text);
    if (!parsed) {
      throw new Error("invalid_analysis_json");
    }

    const verifiedCount = contracts.filter((contract) => contract.is_verified).length;
    const proxyCount = contracts.filter((contract) => contract.proxy.is_proxy).length;

    return {
      explanation: parsed.explanation || "",
      root_cause: parsed.root_cause || aiExtraction?.root_cause || "",
      attack_steps: parsed.attack_steps || [],
      vulnerability_type:
        parsed.vulnerability_type || aiExtraction?.vulnerability_type || "",
      mitigation: this.mitigationEnabled ? (parsed.mitigation || []) : [],
      confidence: {
        score: Math.min(
          0.5 +
            Math.min(verifiedCount * 0.1, 0.3) +
            (aiExtraction ? 0.15 : 0) +
            (proxyCount > 0 ? 0.1 : 0),
          1,
        ),
        factors: {
          verified_contracts: verifiedCount > 0,
          has_source_code: contracts.some((contract) => contract.source_code),
          known_pattern_match: Boolean(aiExtraction),
        },
        reasoning: `${verifiedCount} verified, ${proxyCount} proxy`,
      },
    };
  }

  private async withRetry<T>(
    operation: "extraction" | "analysis",
    pocId: string,
    fn: () => Promise<T>,
  ): Promise<T> {
    return await asyncRetry(fn, {
      maxAttempts: AI_RETRY_ATTEMPTS,
      initialDelayMs: AI_RETRY_INITIAL_DELAY_MS,
      maxDelayMs: AI_RETRY_MAX_DELAY_MS,
      backoffMultiplier: 2,
      shouldRetry: async (error) => this.isRetryableAIError(error),
      onRetry: async (error, attempt) => {
        logger.debug(
          `AI ${operation} retry ${attempt + 1}/${AI_RETRY_ATTEMPTS} for ${pocId}: ${error.message}`,
        );
      },
    });
  }

  private isRetryableAIError(error: Error): boolean {
    const message = error.message.toLowerCase();
    const retryableHints = [
      "429",
      "rate limit",
      "temporar",
      "timeout",
      "timed out",
      "network",
      "fetch",
      "503",
      "502",
      "overloaded",
      "econnreset",
      "socket hang up",
      "invalid_extract",
      "invalid_extraction_json",
      "no_tool_calls",
    ];

    return retryableHints.some((hint) => message.includes(hint));
  }

  private parseJsonPayload<T>(text: string): T | null {
    const trimmed = text.trim();

    try {
      return JSON.parse(trimmed) as T;
    } catch {
      // Fall back to extraction from any JSON object in the response.
    }

    const codeBlockMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (codeBlockMatch && codeBlockMatch[1]) {
      try {
        return JSON.parse(codeBlockMatch[1].trim()) as T;
      } catch {
        // Continue.
      }
    }

    const objectMatch = trimmed.match(/\{[\s\S]*\}/);
    if (objectMatch && objectMatch[0]) {
      try {
        return JSON.parse(objectMatch[0]) as T;
      } catch {
        return null;
      }
    }

    return null;
  }

  private normalizeExtractedContractInfo(
    raw: unknown,
  ): ExtractedContractInfo | null {
    if (!raw || typeof raw !== "object") {
      return null;
    }

    const input = raw as {
      vulnerable_contracts?: unknown;
      attack_summary?: unknown;
      vulnerability_type?: unknown;
      root_cause?: unknown;
    };

    if (!Array.isArray(input.vulnerable_contracts)) {
      return null;
    }

    const normalizedContracts: ExtractedContractInfo["vulnerable_contracts"] = [];
    const seen = new Set<string>();

    for (const item of input.vulnerable_contracts) {
      if (!item || typeof item !== "object") {
        continue;
      }
      const contract = item as {
        address?: unknown;
        role?: unknown;
        chain_id?: unknown;
        reason?: unknown;
      };

      if (
        typeof contract.address !== "string" ||
        !/^0x[a-fA-F0-9]{40}$/.test(contract.address.trim())
      ) {
        continue;
      }

      if (
        contract.role !== "vulnerable" &&
        contract.role !== "attacker" &&
        contract.role !== "helper"
      ) {
        continue;
      }

      const chainId =
        typeof contract.chain_id === "number"
          ? contract.chain_id
          : Number.parseInt(String(contract.chain_id ?? ""), 10);

      if (!Number.isFinite(chainId) || chainId <= 0) {
        continue;
      }

      const address = contract.address.toLowerCase();
      const dedupeKey = `${chainId}:${address}`;
      if (seen.has(dedupeKey)) {
        continue;
      }
      seen.add(dedupeKey);

      normalizedContracts.push({
        address,
        role: contract.role,
        chain_id: chainId,
        reason:
          typeof contract.reason === "string" && contract.reason.trim().length > 0
            ? contract.reason.trim()
            : "AI extracted",
      });
    }

    if (normalizedContracts.length === 0) {
      return null;
    }

    return {
      vulnerable_contracts: normalizedContracts,
      attack_summary:
        typeof input.attack_summary === "string" ? input.attack_summary : "",
      vulnerability_type:
        typeof input.vulnerability_type === "string"
          ? input.vulnerability_type
          : "",
      root_cause: typeof input.root_cause === "string" ? input.root_cause : "",
    };
  }

  private combineAndMinifySourceForAI(sourceCode: string | undefined): string {
    if (!sourceCode || sourceCode.trim().length === 0) {
      return "";
    }

    const units = this.parseSourceUnits(sourceCode);
    if (units.length === 0) {
      return "";
    }

    return units
      .map((unit, index) => {
        const minified = this.minifySolidity(unit.content);
        const label = unit.path || `source_${index + 1}.sol`;
        return `/* FILE: ${label} */ ${minified}`;
      })
      .join(" ");
  }

  private parseSourceUnits(
    sourceCode: string,
  ): Array<{ path: string; content: string }> {
    const raw = sourceCode.trim();
    if (raw.length === 0) {
      return [];
    }

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
    if (fromSources.length > 0) {
      return fromSources;
    }

    const fromDirectMap = this.extractFromDirectContentMap(payload);
    if (fromDirectMap.length > 0) {
      return fromDirectMap;
    }

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
    if (!sources || typeof sources !== "object") {
      return [];
    }

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

  private minifySolidity(source: string): string {
    const noBlockComments = source.replace(/\/\*[\s\S]*?\*\//g, " ");
    const noLineComments = noBlockComments.replace(/\/\/.*$/gm, " ");
    return noLineComments.replace(/\s+/g, " ").trim();
  }

  private minifyBytecodeForAI(bytecode: string): string {
    return bytecode.replace(/\s+/g, "").trim();
  }

  private fallbackExtractContractInfo(
    poc: ParsedPOC,
    foundryChains: ChainContext[],
  ): ExtractedContractInfo | null {
    const addressRegex = /\b0x[a-fA-F0-9]{40}\b/g;
    const matches = poc.code.match(addressRegex) ?? [];
    const uniqueAddresses = Array.from(
      new Set(matches.map((address) => address.toLowerCase())),
    );

    if (uniqueAddresses.length === 0) {
      return null;
    }

    const chainId = foundryChains[0]?.chain_id ?? 1;
    const vulnerableContracts = uniqueAddresses.slice(0, 12).map((address) => ({
      address,
      role: "vulnerable" as const,
      chain_id: chainId,
      reason: "fallback_regex_extraction",
    }));

    return {
      vulnerable_contracts: vulnerableContracts,
      attack_summary: "Fallback extraction from address regex",
      vulnerability_type: "",
      root_cause: "",
    };
  }
}

export function createAIClient(): AIClient {
  return new AIClient();
}
