import { createOpenAI } from "@ai-sdk/openai";
import { generateText, tool } from "ai";

import { config, aiConfig, extraction, analysis } from "../config/env";
import { logger } from "../lib/logger";
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

interface ExtractedContractInfo {
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

const extractContractsTool = {
  type: "function" as const,
  name: "extractContracts",
  description: "Extract vulnerable contract addresses from a DeFi exploit POC",
  parameters: {
    type: "object",
    properties: {
      poc_code: { type: "string" },
      title: { type: "string" },
      foundry_chains: { type: "string" },
    },
    required: ["poc_code", "title", "foundry_chains"],
    additionalProperties: false,
  },
};

export class AIClient {
  private extractionClient: ReturnType<typeof createOpenAI> | null = null;
  private analysisClient: ReturnType<typeof createOpenAI> | null = null;
  private extractionModel = "";
  private analysisModel = "";
  private extractionProvider = "";
  private analysisProvider = "";
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

  async extractContractInfo(
    poc: ParsedPOC,
    foundryChains: ChainContext[],
  ): Promise<ExtractedContractInfo | null> {
    if (!this.enabled || !this.extractionClient) {
      return null;
    }

    try {
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

        const text = result.text;
        const jsonMatch = text.match(/\{[\s\S]*\}/);

        if (!jsonMatch) {
          logger.warn(`No JSON found in response for ${poc.id}`);
          return null;
        }

        const parsed = JSON.parse(jsonMatch[0]);

        if (!parsed.vulnerable_contracts || !Array.isArray(parsed.vulnerable_contracts)) {
          logger.warn(`Invalid response structure for ${poc.id}`);
          return null;
        }

        return parsed as ExtractedContractInfo;
      }

      const result = await generateText({
        model: this.extractionClient(this.extractionModel),
        messages: [
          {
            role: "system",
            content: `You are a smart contract security analyzer. Read the POC code and extract contract info.

Extract contract addresses using the tool provided. Be very careful to identify:
- All contract addresses used in the POC (vulnerable, attacker, helper)
- The correct chain_id for each contract
- The role of each contract

Available chains: mainnet=1, bsc=56, polygon=137, arbitrum=42161, base=8453, optimism=10, avax=43114, linea=59144, blast=81457, gnosis=100`,
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
        tools: [extractContractsTool],
        maxSteps: 2,
        temperature: this.temperature,
      });

      const toolCalls = result.toolCalls;
      if (!toolCalls || toolCalls.length === 0) {
        logger.warn(`No tool calls for ${poc.id}`);
        return null;
      }

      return toolCalls[0].args as ExtractedContractInfo;
    } catch (error) {
      console.error(error);
      logger.error(`AI extraction failed for ${poc.id}: ${String(error)}`);
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
      const contractsContext = contracts
        .map((contract) => {
          const verified = contract.is_verified ? "✓" : "✗";
          const proxy = contract.proxy.is_proxy
            ? ` (PROXY→${contract.proxy.implementation_address})`
            : "";
          const name = contract.contract_name
            ? ` [${contract.contract_name}]`
            : "";

          return `- ${contract.address}${name} (${contract.role}, chain${contract.chain_id}, ${verified})${proxy}`;
        })
        .join("\n");

      const verifiedContracts = contracts.filter(
        (contract) => contract.is_verified && contract.source_code,
      );

      const sourceCodeContext =
        verifiedContracts.length > 0
          ? verifiedContracts
              .map(
                (contract) =>
                  `=== ${contract.contract_name || contract.address} ===\n${contract.source_code}`,
              )
              .join("\n\n")
          : "No verified source code";

      const proxyContracts = contracts.filter(
        (contract) => contract.proxy.is_proxy,
      );

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
{"explanation":"...","root_cause":"...","attack_steps":["...",...],"vulnerability_type":"...","mitigation":["...",...],"confidence":{"score":0.0,"factors":{"verified_contracts":true,"has_source_code":true,"known_pattern_match":true},"reasoning":"..."}}`,
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

      const text = result.text;
      const jsonMatch = text.match(/\{[\s\S]*\}/);

      if (!jsonMatch) {
        logger.warn(`Failed to parse JSON for ${poc.id}`);
        return null;
      }

      const parsed = JSON.parse(jsonMatch[0]) as Partial<AnalysisOutput>;
      const verifiedCount = contracts.filter(
        (contract) => contract.is_verified,
      ).length;
      const proxyCount = contracts.filter(
        (contract) => contract.proxy.is_proxy,
      ).length;

      return {
        explanation: parsed.explanation || "",
        root_cause: parsed.root_cause || aiExtraction?.root_cause || "",
        attack_steps: parsed.attack_steps || [],
        vulnerability_type:
          parsed.vulnerability_type || aiExtraction?.vulnerability_type || "",
        mitigation: parsed.mitigation || [],
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
    } catch (error) {
      logger.error(`AI analysis failed for ${poc.id}: ${String(error)}`);
      return null;
    }
  }
}

export function createAIClient(): AIClient {
  return new AIClient();
}
