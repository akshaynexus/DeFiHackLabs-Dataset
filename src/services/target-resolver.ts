import { getChainConfig, getChainIdFromExplorer } from "../domain/chain";
import { logger } from "../lib/logger";
import type {
  TargetResolutionResult,
  ParsedPOC,
} from "../domain/vulnerability";

interface AIExtractedContract {
  address: string;
  role: "vulnerable" | "attacker" | "helper";
  chain_id: number;
  reason: string;
}

export class TargetResolver {
  resolveTargets(
    poc: ParsedPOC,
    aiContracts: AIExtractedContract[] | null = null,
  ): TargetResolutionResult {
    const candidates: TargetResolutionResult["candidates"] = [];
    const resolved: TargetResolutionResult["contracts"] = [];

    // First, use AI-extracted contracts if available (higher confidence)
    if (aiContracts && aiContracts.length > 0) {
      for (const aiContract of aiContracts) {
        const addr = this.normalizeAddress(aiContract.address);
        const chainConfig = getChainConfig(aiContract.chain_id);

        candidates.push({
          address: addr,
          chain_id: aiContract.chain_id,
          chain_name: chainConfig?.name ?? "Unknown",
          confidence: 0.95, // High confidence from AI
          evidence: `AI extracted: ${aiContract.reason}`,
          role: aiContract.role,
          source_hint: `AI: ${aiContract.reason}`,
        });
      }
    }

    // If no AI contracts, fall back to raw addresses from POC
    if (candidates.length === 0) {
      for (const rawAddr of poc.raw_addresses) {
        let chainId = rawAddr.chain_hint
          ? this.detectChainFromHint(rawAddr.chain_hint)
          : null;

        if (!chainId && rawAddr.source.startsWith("comment:")) {
          chainId = this.detectChainFromHint(rawAddr.source);
        }

        chainId = chainId ?? 1;
        const chainConfig = getChainConfig(chainId);
        if (!chainConfig) continue;

        const candidate = {
          address: this.normalizeAddress(rawAddr.address),
          chain_id: chainId,
          chain_name: chainConfig.name,
          confidence: rawAddr.source.startsWith("comment") ? 0.8 : 0.4,
          evidence: rawAddr.source,
          role: rawAddr.role ?? "unknown",
          source_hint: rawAddr.source,
        };

        candidates.push(candidate);
      }
    }

    // Deduplicate by address+chain
    const uniqueMap = new Map<string, (typeof candidates)[0]>();
    for (const c of candidates) {
      const key = `${c.chain_id}-${c.address}`;
      if (
        !uniqueMap.has(key) ||
        uniqueMap.get(key)!.confidence < c.confidence
      ) {
        uniqueMap.set(key, c);
      }
    }

    // Determine resolution status
    let resolution_status: TargetResolutionResult["resolution_status"] =
      "resolved";

    if (uniqueMap.size === 0) {
      resolution_status = "no_contracts_found";
    } else if (uniqueMap.size > 10) {
      resolution_status = "ambiguous_candidates";
    }

    // Build final contracts list
    for (const [, c] of uniqueMap) {
      resolved.push({
        address: c.address,
        role: c.role === "unknown" ? "helper" : c.role,
        chain_id: c.chain_id,
        chain_name: c.chain_name,
        source_hint: c.evidence,
        confidence: c.confidence,
      });
    }

    // Calculate overall confidence
    const avgConfidence =
      resolved.length > 0
        ? resolved.reduce((sum, c) => sum + c.confidence, 0) / resolved.length
        : 0;

    // Determine source
    const source = aiContracts
      ? "ai_extraction"
      : poc.raw_addresses.some((a) => a.source.startsWith("comment"))
        ? "header"
        : poc.raw_addresses.some((a) => a.source === "code_match")
          ? "regex"
          : "unknown";

    return {
      contracts: resolved,
      confidence: avgConfidence,
      source,
      candidates: candidates,
      resolution_status,
    };
  }

  private detectChainFromHint(hint: string): number | null {
    const chainId = getChainIdFromExplorer(hint);
    if (chainId) return chainId;

    const hintLower = hint.toLowerCase();

    if (hintLower.includes("etherscan") || hintLower.includes("ethereum"))
      return 1;
    if (hintLower.includes("bsc") || hintLower.includes("binance")) return 56;
    if (hintLower.includes("polygon") || hintLower.includes("matic"))
      return 137;
    if (hintLower.includes("arbitrum")) return 42161;
    if (hintLower.includes("base")) return 8453;
    if (hintLower.includes("optimism") || hintLower.includes("op")) return 10;
    if (hintLower.includes("avax") || hintLower.includes("avalanche"))
      return 43114;
    if (hintLower.includes("linea")) return 59144;
    if (hintLower.includes("blast")) return 81457;

    return null;
  }

  private normalizeAddress(address: string): string {
    if (!address.startsWith("0x")) {
      address = "0x" + address;
    }
    return address.toLowerCase();
  }
}

export function createTargetResolver(): TargetResolver {
  return new TargetResolver();
}
