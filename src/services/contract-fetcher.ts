import { getChainConfig } from "../domain/chain";
import { createDefaultProxy } from "../domain/vulnerability";
import { type Result, ok, err, isOk } from "../lib/result";
import { logger } from "../lib/logger";
import { FileCache } from "../lib/cache";
import {
  EtherscanClient,
  type EtherscanClient,
} from "../clients/etherscan-client";
import type { Config } from "../config/env";
import type {
  ResolvedContract,
  FetchError,
  ResolutionStatus,
} from "../domain/vulnerability";

export interface ContractFetcherOptions {
  etherscanClient: EtherscanClient;
  cache: FileCache;
  config: Config;
}

export interface ContractWithImplementation {
  proxy: ResolvedContract;
  implementation: ResolvedContract | null;
}

export class ContractFetcher {
  private client: EtherscanClient;
  private cache: FileCache;
  private config: Config;

  constructor(options: ContractFetcherOptions) {
    this.client = options.etherscanClient;
    this.cache = options.cache;
    this.config = options.config;
  }

  async fetchContracts(
    contracts: Array<{
      address: string;
      role: "vulnerable" | "attacker" | "helper" | "unknown";
      chain_id: number;
      chain_name: string;
      source_hint: string;
      confidence: number;
    }>,
  ): Promise<ResolvedContract[]> {
    const results: ResolvedContract[] = [];

    // Fetch in parallel with limit
    const chunkSize = this.config.fetch_parallel;

    for (let i = 0; i < contracts.length; i += chunkSize) {
      const chunk = contracts.slice(i, i + chunkSize);

      const fetches = chunk.map(async (c) => {
        const result = await this.fetchSingleContractWithProxy(c);
        return { input: c, result };
      });

      const responses = await Promise.all(fetches);

      for (const { input, result } of responses) {
        if (isOk(result)) {
          // Add the proxy contract
          results.push(result.data.proxy);
          // Add the implementation contract if it exists and is different
          if (result.data.implementation) {
            results.push(result.data.implementation);
          }
        } else {
          // Add contract with error info
          results.push(this.createFailedContract(input, result.error));
        }
      }
    }

    return results;
  }

  private async fetchSingleContractWithProxy(contract: {
    address: string;
    role: "vulnerable" | "attacker" | "helper" | "unknown";
    chain_id: number;
    chain_name: string;
    source_hint: string;
    confidence: number;
  }): Promise<Result<ContractWithImplementation, FetchError>> {
    // First fetch the main contract
    const mainResult = await this.fetchContractData(contract);

    if (!mainResult.ok) {
      return err(mainResult.error);
    }

    const mainData = mainResult.data;
    const chainConfig = getChainConfig(contract.chain_id);

    // Build the proxy info
    const proxy = createDefaultProxy();
    let implementationAddress: string | null = null;

    if (mainData.isProxy && mainData.implementationAddress) {
      proxy.is_proxy = true;
      proxy.implementation_address =
        mainData.implementationAddress.toLowerCase();
      proxy.proxy_type = "EIP1967";
      proxy.resolution_depth = 1;
      proxy.resolved_at = new Date().toISOString();
      implementationAddress = mainData.implementationAddress.toLowerCase();
    }

    const proxyContract: ResolvedContract = {
      address: contract.address.toLowerCase(),
      role: contract.role,
      source_hint: contract.source_hint,
      chain_id: contract.chain_id,
      chain_name: contract.chain_name,
      is_verified: mainData.isVerified,
      verification_status: mainData.isVerified
        ? mainData.isProxy
          ? "proxy"
          : "verified"
        : mainData.bytecode
          ? "unverified"
          : "not_found",
      source_code: mainData.sourceCode ?? undefined,
      bytecode: mainData.bytecode ?? undefined,
      abi: mainData.abi ?? undefined,
      contract_name: mainData.contractName ?? undefined,
      compiler_version: mainData.compilerVersion ?? undefined,
      proxy,
      explorer_url: chainConfig
        ? `${chainConfig.explorer}/address/${contract.address}`
        : "",
      fetched_at: new Date().toISOString(),
    };

    // If there's a proxy implementation, fetch that too
    let implementationContract: ResolvedContract | null = null;

    if (implementationAddress) {
      const implResult = await this.fetchContractData({
        ...contract,
        address: implementationAddress,
        role: "helper", // Implementation is usually a helper
        source_hint: `implementation of ${contract.address}`,
      });

      if (implResult.ok) {
        const implData = implResult.data;
        const implProxy = createDefaultProxy();

        // Check if implementation is itself a proxy
        if (implData.isProxy && implData.implementationAddress) {
          implProxy.is_proxy = true;
          implProxy.implementation_address =
            implData.implementationAddress.toLowerCase();
          implProxy.proxy_type = "EIP1967";
          implProxy.resolution_depth = 2;
          implProxy.resolved_at = new Date().toISOString();
        }

        implementationContract = {
          address: implementationAddress,
          role: "helper",
          source_hint: `implementation of ${contract.address}`,
          chain_id: contract.chain_id,
          chain_name: contract.chain_name,
          is_verified: implData.isVerified,
          verification_status: implData.isVerified
            ? "verified"
            : implData.bytecode
              ? "unverified"
              : "not_found",
          source_code: implData.sourceCode ?? undefined,
          bytecode: implData.bytecode ?? undefined,
          abi: implData.abi ?? undefined,
          contract_name: implData.contractName ?? undefined,
          compiler_version: implData.compilerVersion ?? undefined,
          proxy: implProxy,
          explorer_url: chainConfig
            ? `${chainConfig.explorer}/address/${implementationAddress}`
            : "",
          fetched_at: new Date().toISOString(),
        };
      }
    }

    return ok({ proxy: proxyContract, implementation: implementationContract });
  }

  private async fetchContractData(contract: {
    address: string;
    role: string;
    chain_id: number;
    chain_name: string;
    source_hint: string;
  }): Promise<
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
    const cacheKey = `contract_${contract.chain_id}_${contract.address}`;

    // Check cache first
    if (this.config.cache_enabled) {
      const cached = await this.cache.get<{
        sourceCode: string | null;
        abi: string | null;
        bytecode: string | null;
        isVerified: boolean;
        contractName: string | null;
        compilerVersion: string | null;
        isProxy: boolean;
        implementationAddress: string | null;
      }>(cacheKey);

      if (cached) {
        logger.debug(`Cache hit for ${contract.address}`);
        return ok(cached, true);
      }
    }

    // Fetch from Etherscan
    const dataResult = await this.client.getContractData(
      contract.address,
      contract.chain_id,
    );

    if (!dataResult.ok) {
      return err(dataResult.error);
    }

    const data = dataResult.data;

    const result = {
      sourceCode: data.sourceCode,
      abi: data.abi,
      bytecode: data.bytecode,
      isVerified: data.isVerified,
      contractName: data.contractName,
      compilerVersion: data.compilerVersion,
      isProxy: data.isProxy,
      implementationAddress: data.implementationAddress,
    };

    // Cache the result
    if (this.config.cache_enabled) {
      await this.cache.set(cacheKey, result);
    }

    return ok(result);
  }

  private async fetchSingleContract(contract: {
    address: string;
    role: "vulnerable" | "attacker" | "helper" | "unknown";
    chain_id: number;
    chain_name: string;
    source_hint: string;
    confidence: number;
  }): Promise<Result<ResolvedContract, FetchError>> {
    const result = await this.fetchSingleContractWithProxy(contract);

    if (!result.ok) {
      return err(result.error);
    }

    return ok(result.data.proxy);
  }

  private createFailedContract(
    contract: {
      address: string;
      role: "vulnerable" | "attacker" | "helper" | "unknown";
      chain_id: number;
      chain_name: string;
      source_hint: string;
    },
    error: FetchError,
  ): ResolvedContract {
    const chainConfig = getChainConfig(contract.chain_id);

    return {
      address: contract.address.toLowerCase(),
      role: contract.role,
      source_hint: contract.source_hint,
      chain_id: contract.chain_id,
      chain_name: contract.chain_name,
      is_verified: false,
      verification_status: "not_found",
      proxy: createDefaultProxy(),
      explorer_url: chainConfig
        ? `${chainConfig.explorer}/address/${contract.address}`
        : "",
      fetched_at: new Date().toISOString(),
      fetch_error: error.type,
    };
  }

  determineResolutionStatus(contracts: ResolvedContract[]): ResolutionStatus {
    if (contracts.length === 0) {
      return "address_not_found";
    }

    const verified = contracts.filter((c) => c.is_verified).length;
    const total = contracts.length;
    const withErrors = contracts.filter((c) => c.fetch_error).length;

    if (withErrors > 0) {
      return "fetch_failed";
    }

    if (verified === 0) {
      return "unverified_contract";
    }

    if (verified < total) {
      return "partial";
    }

    return "resolved";
  }
}

export function createContractFetcher(
  options: ContractFetcherOptions,
): ContractFetcher {
  return new ContractFetcher(options);
}
