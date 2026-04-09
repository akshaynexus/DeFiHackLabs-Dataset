import { ok, err, type Result, type FetchError } from "../lib/result";
import { defaultRateLimiter } from "../lib/rate-limit";
import { asyncRetry } from "../lib/retry";

export interface EtherscanSourceCodeResponse {
  SourceCode: string;
  ABI: string;
  ContractName: string;
  CompilerVersion: string;
  OptimizationUsed: string;
  Runs: string;
  ConstructorArguments: string;
  EVMVersion: string;
  Library: string;
  LicenseType: string;
  Proxy: string;
  Implementation?: string;
  SwarmSource: string;
}

export interface EtherscanAbiResponse {
  status: string;
  message: string;
  result: string;
}

export interface EtherscanProxyResponse {
  jsonrpc: string;
  id: number;
  result: string;
}

export type ApiTier = "free" | "paid";

export const FREE_TIER_CHAINS = new Set([
  1, // Ethereum Mainnet
  11155111, // Sepolia
  137, // Polygon
  80002, // Polygon Amoy
  42161, // Arbitrum One
  421614, // Arbitrum Sepolia
  59144, // Linea
  59141, // Linea Sepolia
  81457, // Blast
  168587773, // Blast Sepolia
  100, // Gnosis
  5000, // Mantle
  5003, // Mantle Sepolia
  534352, // Scroll
  534351, // Scroll Sepolia
  167000, // Taiko
  167013, // Taiko Hoodi
  1328, // Sei
  1329, // Sei Devnet
]);

// V2 base URL - single endpoint for all chains
const V2_BASE_URL = "https://api.etherscan.io/v2/api";

export class EtherscanClient {
  private apiKey: string;
  private tier: ApiTier;
  private rateLimiter = defaultRateLimiter;

  constructor(apiKey: string, tier: ApiTier = "free") {
    if (!apiKey || apiKey === "YourApiKeyToken") {
      throw new Error(
        "ETHERSCAN_API_KEY is required. Get one from https://etherscan.io/apis",
      );
    }
    this.apiKey = apiKey;
    this.tier = tier;
  }

  isChainSupported(chainId: number): boolean {
    if (this.tier === "paid") {
      return true; // Paid tier supports all chains
    }
    return FREE_TIER_CHAINS.has(chainId);
  }

  getUnsupportedChains(): number[] {
    if (this.tier === "paid") {
      return [];
    }
    return Array.from(FREE_TIER_CHAINS);
  }

  private async makeRequest<T>(
    chainId: number,
    params: Record<string, string>,
  ): Promise<Result<T, FetchError>> {
    // Check tier support
    if (!this.isChainSupported(chainId)) {
      return err({
        type: "invalid_chain",
        supported: Array.from(FREE_TIER_CHAINS),
      } as FetchError);
    }

    const allParams = {
      chainid: String(chainId),
      apikey: this.apiKey,
      ...params,
    };

    const url = `${V2_BASE_URL}?${new URLSearchParams(allParams)}`;

    try {
      await this.rateLimiter.acquire(`etherscan-${chainId}`, 1);

      const response = await asyncRetry(
        async () => {
          const res = await fetch(url, {
            method: "GET",
            headers: { "Content-Type": "application/json" },
          });
          return res;
        },
        {
          maxAttempts: 3,
          initialDelayMs: 1000,
          maxDelayMs: 10000,
          shouldRetry: async (error: Error) => {
            return (
              error.message.includes("fetch") || error.message.includes("rate")
            );
          },
        },
      );

      if (!response.ok) {
        if (response.status === 429) {
          return err({
            type: "rate_limited",
            retry_after: 60,
          } as FetchError);
        }
        return err({
          type: "api_error",
          code: String(response.status),
          message: response.statusText,
        } as FetchError);
      }

      const data = (await response.json()) as T;

      // Check for API-level errors (status: "0")
      const errorCheck = data as {
        status?: string;
        message?: string;
        result?: string;
      };
      if (errorCheck.status === "0") {
        const resultStr = String(errorCheck.result || "");
        if (
          resultStr.includes("Invalid API Key") ||
          resultStr.includes("missing")
        ) {
          return err({
            type: "api_error",
            code: "INVALID_KEY",
            message: resultStr || "Invalid API key",
          } as FetchError);
        }
        if (resultStr.includes("rate")) {
          return err({
            type: "rate_limited",
            retry_after: 60,
          } as FetchError);
        }
        return err({
          type: "api_error",
          code: "API_ERROR",
          message: resultStr,
        } as FetchError);
      }

      return ok(data, false);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes("fetch") || message.includes("network")) {
        return err({ type: "network_error", message } as FetchError);
      }
      return err({
        type: "api_error",
        code: "UNKNOWN",
        message,
      } as FetchError);
    }
  }

  async getSourceCode(
    address: string,
    chainId: number,
  ): Promise<Result<EtherscanSourceCodeResponse, FetchError>> {
    const result = await this.makeRequest<EtherscanSourceCodeResponse>(
      chainId,
      {
        module: "contract",
        action: "getsourcecode",
        address,
      },
    );

    if (!result.ok) {
      return result;
    }

    const data = result.data as unknown as {
      status: string;
      message: string;
      result: EtherscanSourceCodeResponse[];
    };

    if (data.status !== "1" || !data.result || data.result.length === 0) {
      return err({
        type: "not_found",
        reason: "no_contract",
      } as FetchError);
    }

    return ok(data.result[0], false);
  }

  async getAbi(
    address: string,
    chainId: number,
  ): Promise<Result<string, FetchError>> {
    const result = await this.makeRequest<EtherscanAbiResponse>(chainId, {
      module: "contract",
      action: "getabi",
      address,
    });

    if (!result.ok) {
      return result;
    }

    const data = result.data;

    if (data.status !== "1") {
      return err({
        type: "not_found",
        reason: "no_contract",
      } as FetchError);
    }

    return ok(data.result, false);
  }

  async getBytecode(
    address: string,
    chainId: number,
  ): Promise<Result<string, FetchError>> {
    const result = await this.makeRequest<EtherscanProxyResponse>(chainId, {
      module: "proxy",
      action: "eth_getCode",
      address,
      tag: "latest",
    });

    if (!result.ok) {
      return result;
    }

    const data = result.data;

    if (data.result === "0x" || !data.result) {
      return err({
        type: "not_found",
        reason: "no_contract",
      } as FetchError);
    }

    return ok(data.result, false);
  }

  async getContractData(
    address: string,
    chainId: number,
  ): Promise<
    Result<
      {
        sourceCode: string | null;
        abi: string | null;
        bytecode: string | null;
        isVerified: boolean;
        contractName: string | null;
        compilerVersion: string | null;
        isProxy: boolean;
        implementationAddress: string | null;
      },
      FetchError
    >
  > {
    const [sourceResult, bytecodeResult] = await Promise.all([
      this.getSourceCode(address, chainId),
      this.getBytecode(address, chainId),
    ]);

    if (!sourceResult.ok && !bytecodeResult.ok) {
      return err(sourceResult.error);
    }

    const sourceCode =
      sourceResult.ok && sourceResult.data?.SourceCode
        ? sourceResult.data.SourceCode
        : null;

    const abi =
      sourceResult.ok && sourceResult.data?.ABI ? sourceResult.data.ABI : null;

    const bytecode = bytecodeResult.ok ? bytecodeResult.data : null;

    const isVerified = !!(sourceCode && sourceCode.length > 0);
    const contractName = sourceResult.ok
      ? (sourceResult.data?.ContractName ?? null)
      : null;
    const compilerVersion = sourceResult.ok
      ? (sourceResult.data?.CompilerVersion ?? null)
      : null;
    const isProxy = sourceResult.ok && sourceResult.data?.Proxy === "1";
    const implementationAddress = sourceResult.ok
      ? (sourceResult.data?.Implementation ?? null)
      : null;

    return ok({
      sourceCode,
      abi,
      bytecode,
      isVerified,
      contractName,
      compilerVersion,
      isProxy,
      implementationAddress,
    });
  }
}

export function createEtherscanClient(
  apiKey: string,
  tier: ApiTier = "free",
): EtherscanClient {
  return new EtherscanClient(apiKey, tier);
}
