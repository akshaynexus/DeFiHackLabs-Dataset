import { createOpenAI } from '@ai-sdk/openai';
import { generateText, tool } from 'ai';
import { z } from 'zod';
import type { Config } from '../config/env';
import { logger } from '../lib/logger';
import type { ParsedPOC, AnalysisOutput, ResolvedContract } from '../domain/vulnerability';

// Map Foundry RPC endpoints to chain IDs
const RPC_TO_CHAIN: Record<string, number> = {
  'mainnet': 1,
  'ethereum': 1,
  'sepolia': 11155111,
  'goerli': 5,
  'bsc': 56,
  'binance': 56,
  'polygon': 137,
  'matic': 137,
  'arbitrum': 42161,
  'optimism': 10,
  'op': 10,
  'avalanche': 43114,
  'avax': 43114,
  'base': 8453,
  'linea': 59144,
  'blast': 81457,
  'gnosis': 100,
  'celo': 42220,
  'mantle': 5000,
  'fantom': 250,
  'sei': 1328,
  'scroll': 534352,
  'taiko': 167000,
};

export interface ChainContext {
  chain_id: number;
  chain_name: string;
  rpc_url: string;
  source: 'foundry' | 'explorer' | 'ai';
}

// Setup OpenAI-compatible client pointing to OpenRouter
function createOpenRouterClient(config: Config) {
  return createOpenAI({
    baseURL: 'https://openrouter.ai/api/v1',
    apiKey: config.openrouter_api_key,
    headers: {
      'HTTP-Referer': 'https://defihacklabs-dataset.local',
      'X-Title': 'DeFi Vulnerability Dataset Generator',
    },
  });
}

// Parse foundry.toml to extract RPC endpoints and infer chain
export function parseFoundryChains(foundryContent: string): ChainContext[] {
  const chains: ChainContext[] = [];
  const lines = foundryContent.split('\n');
  let inRpcSection = false;

  for (const line of lines) {
    const trimmed = line.trim();
    
    if (trimmed === '[rpc_endpoints]') {
      inRpcSection = true;
      continue;
    }
    
    if (inRpcSection && trimmed.startsWith('[')) {
      inRpcSection = false;
    }
    
    if (inRpcSection && trimmed.includes('=')) {
      const [name, url] = trimmed.split('=').map(s => s.trim());
      if (name && url) {
        const chainId = RPC_TO_CHAIN[name.toLowerCase()];
        if (chainId) {
          chains.push({
            chain_id: chainId,
            chain_name: name,
            rpc_url: url.replace(/"/g, ''),
            source: 'foundry',
          });
        }
      }
    }
  }

  return chains;
}

// Tool to extract vulnerable contract info from POC
const extractContractsTool = tool({
  description: 'Extract vulnerable contract addresses and metadata from a DeFi exploit POC',
  inputSchema: z.object({
    poc_code: z.string().describe('The Solidity POC code to analyze'),
    title: z.string().describe('Title/name of the exploit'),
    foundry_chains: z.string().describe('Available chains from foundry.toml (JSON array)'),
  }),
  outputSchema: z.object({
    vulnerable_contracts: z.array(z.object({
      address: z.string().describe('Contract address (0x...)'),
      role: z.enum(['vulnerable', 'attacker', 'helper']),
      chain_id: z.number().describe('Ethereum chain ID (1=ETH, 56=BSC, etc)'),
      reason: z.string().describe('Why this contract is involved in the exploit'),
    })),
    attack_summary: z.string().describe('Brief one-line attack summary'),
    vulnerability_type: z.string().describe('Type of vulnerability'),
    root_cause: z.string().describe('Why the attack was possible'),
  }),
});

export class OpenRouterClient {
  private client: ReturnType<typeof createOpenRouterClient> | null = null;
  private model: string;
  private cheapModel: string;
  private temperature: number;
  private enabled: boolean;

  constructor(config: Config) {
    if (!config.ai_enabled || !config.openrouter_api_key) {
      this.enabled = false;
      this.client = null;
      this.model = '';
      this.cheapModel = 'openai/gpt-4o-mini';
      this.temperature = 0;
      logger.info('AI client disabled');
      return;
    }

    this.enabled = true;
    this.client = createOpenRouterClient(config);
    this.model = config.ai_model;
    this.cheapModel = config.ai_model.includes('mini') || config.ai_model.includes('flash')
      ? config.ai_model
      : 'openai/gpt-4o-mini';
    this.temperature = config.ai_temperature;
    logger.info(`AI client enabled. Extraction: ${this.cheapModel}, Analysis: ${this.model}`);
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  getCheapModel(): string {
    return this.cheapModel;
  }

  getMainModel(): string {
    return this.model;
  }

  async extractContractInfo(
    poc: ParsedPOC,
    foundryChains: ChainContext[]
  ): Promise<{
    vulnerable_contracts: Array<{
      address: string;
      role: 'vulnerable' | 'attacker' | 'helper';
      chain_id: number;
      reason: string;
    }>;
    attack_summary: string;
    vulnerability_type: string;
    root_cause: string;
  } | null> {
    if (!this.enabled || !this.client) {
      return null;
    }

    try {
      const chainsJson = JSON.stringify(foundryChains.map(c => ({
        chain_id: c.chain_id,
        chain_name: c.chain_name,
        source: c.source,
      })));

      const result = await generateText({
        model: this.client(this.cheapModel),
        messages: [
          {
            role: 'system',
            content: `You are a smart contract security analyzer. Analyze DeFi exploit POCs and extract contract information.

Return a JSON object with:
- vulnerable_contracts: Array of {address, role, chain_id, reason}
  - role: "vulnerable" = exploited protocol contract, "attacker" = attack contract, "helper" = token/interface
- attack_summary: One sentence describing the attack
- vulnerability_type: Category (reentrancy, flash loan, oracle manipulation, access control, etc)
- root_cause: Why the attack was possible (the vulnerability)

Use the foundry_chains info to determine the correct chain_id:
- mainnet/ethereum = 1, bsc/binance = 56, polygon/matic = 137
- arbitrum = 42161, base = 8453, optimism/op = 10
- avalanche/avax = 43114, linea = 59144, blast = 81457, gnosis = 100

Extract addresses from variable declarations like:
- address xxx = 0x...
- IERC20(xxx), ContractName(xxx)`,
          },
          {
            role: 'user',
            content: `Analyze this POC:

Title: ${poc.title}
Attack Title: ${poc.attack_title}

Available chains from foundry.toml:
${chainsJson}

POC Code (first 8000 chars):
${poc.code.substring(0, 8000)}`,
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

      return toolCalls[0].args as {
        vulnerable_contracts: Array<{
          address: string;
          role: 'vulnerable' | 'attacker' | 'helper';
          chain_id: number;
          reason: string;
        }>;
        attack_summary: string;
        vulnerability_type: string;
        root_cause: string;
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error(`AI extraction failed for ${poc.id}: ${message}`);
      return null;
    }
  }

  async analyzeExploit(
    poc: ParsedPOC,
    contracts: ResolvedContract[],
    aiExtraction: {
      attack_summary: string;
      vulnerability_type: string;
      root_cause: string;
    } | null,
    foundryChains: ChainContext[]
  ): Promise<AnalysisOutput | null> {
    if (!this.enabled || !this.client) {
      return null;
    }

    try {
      // Build rich contract context with proxy info and source code
      const contractsContext = contracts.map(c => {
        const verified = c.is_verified ? '✓ verified' : '✗ unverified';
        const proxyInfo = c.proxy.is_proxy 
          ? ` (PROXY → ${c.proxy.implementation_address})` 
          : '';
        const name = c.contract_name ? ` [${c.contract_name}]` : '';
        return `- ${c.address}${name} (${c.role}, chain ${c.chain_id}, ${verified})${proxyInfo}`;
      }).join('\n');

      // Include source code from verified contracts
      const verifiedContracts = contracts.filter(c => c.is_verified && c.source_code);
      const sourceCodeContext = verifiedContracts.length > 0
        ? verifiedContracts.map(c => `
=== ${c.contract_name || c.address} ===
${c.source_code?.substring(0, 3000) ?? 'No source available'}
`).join('\n')
        : '';

      // Get proxy contracts specifically
      const proxyContracts = contracts.filter(c => c.proxy.is_proxy);
      const proxyContext = proxyContracts.length > 0
        ? `\nProxy Contracts Identified:\n${proxyContracts.map(c => 
          `- ${c.address} → Implementation: ${c.proxy.implementation_address}`
        ).join('\n')}`
        : '';

      const chainsContext = foundryChains.length > 0
        ? `Attacked chains (from foundry.toml): ${foundryChains.map(c => c.chain_name).join(', ')}`
        : 'Chain info not available';

      const result = await generateText({
        model: this.client(this.model),
        messages: [
          {
            role: 'system',
            content: `You are a smart contract security analyst. Analyze DeFi exploits and provide detailed technical analysis.

Return JSON with:
- explanation: How the exploit works (1-2 paragraphs) - be technical and specific
- root_cause: The core vulnerability with contract-level details
- attack_steps: Array of 5-7 detailed step-by-step attack instructions
- vulnerability_type: Category (reentrancy, flash loan, oracle manipulation, access control, etc)
- mitigation: Array of 3-5 recommended fixes with specific patterns

IMPORTANT CONTEXT PROVIDED:
- AI extraction has already identified vulnerable contracts and root cause
- Proxy contracts have been resolved to their implementations
- Contract names and verification status are provided

Use this rich context to provide the most accurate analysis possible.`,
          },
          {
            role: 'user',
            content: `Analyze this DeFi exploit in detail:

Title: ${poc.title}
Attack Title: ${poc.attack_title}

AI Extraction Context:
- Attack Summary: ${aiExtraction?.attack_summary ?? 'Not available'}
- Vulnerability Type: ${aiExtraction?.vulnerability_type ?? 'Not available'}
- Root Cause: ${aiExtraction?.root_cause ?? 'Not available'}

${chainsContext}
${proxyContext}

Contracts Found (with details):
${contractsContext}

=== VERIFIABLE CONTRACT SOURCE CODE ===
${sourceCodeContext || 'No verified source code available'}

=== FULL POC CODE (Foundry Test) ===
${poc.code}`,
          },
        ],
        temperature: this.temperature,
        maxTokens: 4000,
      });

      const text = result.text;
      
      // Try to parse JSON from response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        logger.warn(`Failed to parse AI response as JSON for ${poc.id}`);
        return null;
      }

      const parsed = JSON.parse(jsonMatch[0]);
      
      // Calculate confidence based on verification and proxy info
      const verifiedCount = contracts.filter(c => c.is_verified).length;
      const proxyCount = contracts.filter(c => c.proxy.is_proxy).length;
      const hasAiContext = !!aiExtraction;
      const hasProxyContext = proxyCount > 0;
      
      const baseScore = 0.5;
      const verifiedScore = Math.min(verifiedCount * 0.1, 0.3);
      const aiScore = hasAiContext ? 0.15 : 0;
      const proxyScore = hasProxyContext ? 0.1 : 0;
      
      return {
        explanation: parsed.explanation || '',
        root_cause: parsed.root_cause || aiExtraction?.root_cause || '',
        attack_steps: parsed.attack_steps || [],
        vulnerability_type: parsed.vulnerability_type || aiExtraction?.vulnerability_type || '',
        mitigation: parsed.mitigation || [],
        confidence: {
          score: Math.min(baseScore + verifiedScore + aiScore + proxyScore, 1.0),
          factors: {
            verified_contracts: verifiedCount > 0,
            has_source_code: contracts.some(c => c.source_code),
            known_pattern_match: hasAiContext,
          },
          reasoning: `Analysis with ${verifiedCount} verified, ${proxyCount} proxy contracts. AI context: ${hasAiContext ? 'yes' : 'no'}.`,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error(`AI analysis failed for ${poc.id}: ${message}`);
      return null;
    }
  }
}

export function createOpenRouterClient(config: Config): OpenRouterClient {
  return new OpenRouterClient(config);
}
