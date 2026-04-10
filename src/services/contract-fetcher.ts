import { getChainConfig } from "../domain/chain";
import { createDefaultProxy } from "../domain/vulnerability";
import { type Result, type FetchError, ok, err, isOk } from "../lib/result";
import { logger } from "../lib/logger";
import { FileCache } from "../lib/cache";
import { EtherscanClient } from "../clients/etherscan-client";
import type { Config } from "../config/env";
import type {
  ResolvedContract,
  ResolutionStatus,
} from "../domain/vulnerability";
import { readFile } from "fs/promises";
import { isAbsolute, join, relative } from "path";

export interface ContractFetcherOptions {
  etherscanClient: EtherscanClient;
  cache: FileCache;
  config: Config;
}

export interface ContractWithImplementation {
  proxy: ResolvedContract;
  implementation: ResolvedContract | null;
}

interface LocalContractArtifactEntry {
  address: string;
  chainId: number;
  role: "vulnerable" | "attacker" | "helper" | "unknown";
  chainName: string;
  contractName: string | null;
  verificationStatus: string;
  sourceFiles: string[];
  artifactDir: string;
}

interface CachedContractData {
  sourceCode: string | null;
  abi: string | null;
  bytecode: string | null;
  isVerified: boolean;
  contractName: string | null;
  compilerVersion: string | null;
  isProxy: boolean;
  implementationAddress: string | null;
}

export class ContractFetcher {
  private client: EtherscanClient;
  private cache: FileCache;
  private config: Config;
  private localArtifactsIndexPromise: Promise<Map<string, LocalContractArtifactEntry>> | null =
    null;

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
    const uniqueContracts = this.deduplicateContracts(contracts);

    if (uniqueContracts.length !== contracts.length) {
      logger.debug(
        `Deduplicated ${contracts.length - uniqueContracts.length} duplicate contract targets`,
      );
    }

    const chunkSize = Math.max(1, this.config.fetch_parallel);

    for (let i = 0; i < uniqueContracts.length; i += chunkSize) {
      const chunk = uniqueContracts.slice(i, i + chunkSize);

      const fetches = chunk.map(async (contract) => {
        const result = await this.fetchSingleContractWithProxy(contract);
        return { input: contract, result };
      });

      const responses = await Promise.allSettled(fetches);

      for (const [j, settled] of responses.entries()) {
        const input = chunk[j];
        if (!input) continue;

        if (settled.status === "rejected") {
          logger.warn(
            `Unexpected fetch failure for ${input.address}: ${String(settled.reason)}`,
          );
          results.push(
            this.createFailedContract(input, {
              type: "api_error",
              code: "FETCH_CRASH",
              message: String(settled.reason),
            }),
          );
          continue;
        }

        const { result } = settled.value;
        if (isOk(result)) {
          results.push(result.data.proxy);
          if (result.data.implementation) {
            results.push(result.data.implementation);
          }
          continue;
        }

        results.push(this.createFailedContract(input, result.error));
      }
    }

    return results;
  }

  private deduplicateContracts(
    contracts: Array<{
      address: string;
      role: "vulnerable" | "attacker" | "helper" | "unknown";
      chain_id: number;
      chain_name: string;
      source_hint: string;
      confidence: number;
    }>,
  ) {
    const deduped = new Map<string, (typeof contracts)[number]>();

    for (const contract of contracts) {
      const normalizedAddress = contract.address.toLowerCase();
      const key = `${contract.chain_id}:${normalizedAddress}`;
      const existing = deduped.get(key);
      if (!existing || existing.confidence < contract.confidence) {
        deduped.set(key, {
          ...contract,
          address: normalizedAddress,
        });
      }
    }

    return Array.from(deduped.values());
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
  }): Promise<Result<CachedContractData, FetchError>> {
    const cacheKey = `contract_${contract.chain_id}_${contract.address}`;

    const localArtifact = await this.getLocalContractFromArtifacts(
      contract.chain_id,
      contract.address,
    );
    if (localArtifact && (localArtifact.sourceCode || localArtifact.bytecode)) {
      if (this.config.cache_enabled) {
        await this.cache.set(cacheKey, localArtifact);
      }
      logger.debug(`Local artifact hit for ${contract.address}`);
      return ok(localArtifact, true);
    }

    // Check cache first
    if (this.config.cache_enabled) {
      const cached = await this.cache.get<CachedContractData>(cacheKey);

      if (cached) {
        if (!cached.sourceCode && !cached.bytecode) {
          logger.debug(
            `Cache entry without source/bytecode for ${contract.address}; retrying fetch`,
          );
        } else {
          logger.debug(`Cache hit for ${contract.address}`);
          return ok(cached, true);
        }
      }
    }

    // Fetch from Etherscan only if source/bytecode still unavailable locally.
    const dataResult = await this.client.getContractData(
      contract.address,
      contract.chain_id,
    );

    if (!dataResult.ok) {
      return err(dataResult.error);
    }

    const data = dataResult.data;

    const result: CachedContractData = {
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

  private async getLocalContractFromArtifacts(
    chainId: number,
    address: string,
  ): Promise<CachedContractData | null> {
    const index = await this.loadLocalArtifactsIndex();
    const key = `${chainId}:${address.toLowerCase()}`;
    const entry = index.get(key);
    if (!entry) {
      return null;
    }

    const sourceUnits: Array<{ path: string; content: string }> = [];
    let bytecode: string | null = null;

    for (const sourceFile of entry.sourceFiles) {
      const normalized = sourceFile.replace(/\\/g, "/");
      if (normalized.endsWith("/NO_SOURCE.txt") || normalized.endsWith("NO_SOURCE.txt")) {
        continue;
      }
      if (normalized.endsWith("/bytecode.txt") || normalized.endsWith("bytecode.txt")) {
        const bytecodeRaw = await this.readTextIfExists(sourceFile);
        const trimmed = bytecodeRaw?.trim();
        if (trimmed && trimmed.length > 0) {
          bytecode = trimmed;
        }
        continue;
      }
      if (!normalized.endsWith(".sol")) {
        continue;
      }

      const content = await this.readTextIfExists(sourceFile);
      if (!content || content.trim().length === 0) {
        continue;
      }
      sourceUnits.push({
        path: this.toPosixPath(relative(entry.artifactDir, sourceFile)),
        content,
      });
    }

    if (sourceUnits.length === 0 && !bytecode) {
      return null;
    }

    const sourceCode =
      sourceUnits.length === 0
        ? null
        : sourceUnits.length === 1 && sourceUnits[0]
          ? sourceUnits[0].content
          : JSON.stringify({
              sources: Object.fromEntries(
                sourceUnits.map((unit) => [unit.path, { content: unit.content }]),
              ),
            });

    return {
      sourceCode,
      abi: null,
      bytecode,
      isVerified:
        sourceUnits.length > 0 ||
        entry.verificationStatus === "verified" ||
        entry.verificationStatus === "proxy",
      contractName: entry.contractName,
      compilerVersion: null,
      isProxy: entry.verificationStatus === "proxy",
      implementationAddress: null,
    };
  }

  private async loadLocalArtifactsIndex(): Promise<Map<string, LocalContractArtifactEntry>> {
    if (!this.localArtifactsIndexPromise) {
      this.localArtifactsIndexPromise = this.buildLocalArtifactsIndex();
    }
    return await this.localArtifactsIndexPromise;
  }

  private async buildLocalArtifactsIndex(): Promise<Map<string, LocalContractArtifactEntry>> {
    const index = new Map<string, LocalContractArtifactEntry>();
    const manifestPath = join(this.config.contracts_dir, "manifest.json");

    try {
      const raw = await readFile(manifestPath, "utf-8");
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== "object") {
        return index;
      }

      const pocs = (parsed as { pocs?: unknown[] }).pocs;
      if (!Array.isArray(pocs)) {
        return index;
      }

      for (const poc of pocs) {
        if (!poc || typeof poc !== "object") continue;
        const contracts = (poc as { contracts?: unknown[] }).contracts;
        if (!Array.isArray(contracts)) continue;

        for (const contract of contracts) {
          if (!contract || typeof contract !== "object") continue;
          const input = contract as {
            address?: unknown;
            chain_id?: unknown;
            chain_name?: unknown;
            role?: unknown;
            contract_name?: unknown;
            verification_status?: unknown;
            source_files?: unknown;
            artifact_dir?: unknown;
          };
          if (
            typeof input.address !== "string" ||
            typeof input.chain_id !== "number" ||
            typeof input.artifact_dir !== "string" ||
            !Array.isArray(input.source_files)
          ) {
            continue;
          }

          const resolvedSourceFiles = input.source_files
            .filter((file): file is string => typeof file === "string")
            .map((file) => this.resolvePath(file));
          const artifactDir = this.resolvePath(input.artifact_dir);
          const key = `${input.chain_id}:${input.address.toLowerCase()}`;

          index.set(key, {
            address: input.address.toLowerCase(),
            chainId: input.chain_id,
            role: this.normalizeRole(input.role),
            chainName: typeof input.chain_name === "string" ? input.chain_name : "",
            contractName: typeof input.contract_name === "string" ? input.contract_name : null,
            verificationStatus:
              typeof input.verification_status === "string"
                ? input.verification_status
                : "not_found",
            sourceFiles: resolvedSourceFiles,
            artifactDir,
          });
        }
      }
    } catch {
      return index;
    }

    return index;
  }

  private resolvePath(pathLike: string): string {
    if (isAbsolute(pathLike)) {
      return pathLike;
    }
    return join(process.cwd(), pathLike);
  }

  private toPosixPath(path: string): string {
    return path.replace(/\\/g, "/");
  }

  private normalizeRole(
    role: unknown,
  ): "vulnerable" | "attacker" | "helper" | "unknown" {
    if (role === "vulnerable" || role === "attacker" || role === "helper") {
      return role;
    }
    return "unknown";
  }

  private async readTextIfExists(path: string): Promise<string | null> {
    try {
      return await readFile(path, "utf-8");
    } catch {
      return null;
    }
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
