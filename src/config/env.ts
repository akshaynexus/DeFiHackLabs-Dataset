import { CHAIN_CONFIG } from "../domain/chain";

export type ApiTier = "free" | "paid";

export interface Config {
  // AI
  ai_api_key: string;
  ai_extraction_model: string;
  ai_analysis_model: string;
  ai_enabled: boolean;
  ai_temperature: number;

  // Etherscan
  etherscan_api_key: string;
  etherscan_tier: ApiTier;

  // Pipeline
  cache_enabled: boolean;
  cache_ttl_seconds: number;
  rate_limit_rps: number;

  // Concurrency
  fetch_parallel: number;
  ai_parallel: number;
  ai_delay_ms: number;

  // Output
  input_dir: string;
  output_dir: string;
  cache_dir: string;
  idempotency_dir: string;
  chunk_size: number;
  idempotency_strategy: "skip" | "overwrite";

  // Processing
  test_limit: number | null;
}

function getEnv(key: string, defaultValue = ""): string {
  return process.env[key] ?? defaultValue;
}

function getEnvBool(key: string, defaultValue = false): boolean {
  const val = process.env[key]?.toLowerCase();
  if (val === "true" || val === "1") return true;
  if (val === "false" || val === "0") return false;
  return defaultValue;
}

function getEnvNum(key: string, defaultValue: number): number {
  const val = parseInt(process.env[key] ?? "", 10);
  return isNaN(val) ? defaultValue : val;
}

// Parse model prefix and return provider info
function parseModel(model: string): {
  provider: string;
  base_url: string;
  effective_model: string;
} {
  if (model.startsWith("crof/")) {
    return {
      provider: "crof",
      base_url: "https://crof.ai/v1",
      effective_model: model.substring(5),
    };
  }
  if (model.startsWith("google/")) {
    return {
      provider: "google",
      base_url: "https://generativelanguage.googleapis.com/v1beta/openai/",
      effective_model: model.substring(7),
    };
  }
  // Default to openrouter
  const effective = model.startsWith("openrouter/")
    ? model.substring(11)
    : model;
  return {
    provider: "openrouter",
    base_url: "https://openrouter.ai/api/v1",
    effective_model: effective,
  };
}

// Get API key based on provider
function getAPIKey(provider: string): string {
  const openrouterKey = getEnv("OPENROUTER_API_KEY", "");
  const crofKey = getEnv("CROF_API_KEY", "");
  const geminiKey = getEnv("GEMINI_API_KEY", "");

  switch (provider) {
    case "crof":
      return crofKey;
    case "google":
      return geminiKey;
    default:
      return openrouterKey;
  }
}

const etherscanKey = getEnv("ETHERSCAN_API_KEY", "");

// Parse both models - use same provider for both
const extractionRaw = getEnv("AI_EXTRACTION_MODEL", "openrouter/gpt-4o-mini");
const analysisRaw = getEnv("AI_ANALYSIS_MODEL", extractionRaw);

export const extraction = parseModel(extractionRaw);
export const analysis = parseModel(analysisRaw);

// Use extraction provider for API key (both should use same provider)
export const provider = extraction.provider;
const apiKey = getAPIKey(provider);

export const config: Config = {
  // AI
  ai_api_key: apiKey,
  ai_extraction_model: extraction.effective_model,
  ai_analysis_model: analysis.effective_model,
  ai_enabled: getEnvBool("AI_ENABLED", false),
  ai_temperature: getEnvNum("AI_TEMPERATURE", 0.3),

  // Etherscan
  etherscan_api_key: etherscanKey,
  etherscan_tier: getEnv("ETHERSCAN_TIER", "free") as ApiTier,

  // Pipeline
  cache_enabled: getEnvBool("CACHE_ENABLED", true),
  cache_ttl_seconds: getEnvNum("CACHE_TTL_SECONDS", 86400 * 7),
  rate_limit_rps: getEnvNum("RATE_LIMIT_RPS", 5),

  // Concurrency
  fetch_parallel: getEnvNum("FETCH_PARALLEL", 5),
  ai_parallel: getEnvNum("AI_PARALLEL", 1),
  ai_delay_ms: getEnvNum("AI_DELAY_MS", 1000),

  // Output
  input_dir: getEnv("INPUT_DIR", "./data/input/DeFiHackLabs/src/test"),
  output_dir: getEnv("OUTPUT_DIR", "./data/output"),
  cache_dir: getEnv("CACHE_DIR", "./data/cache"),
  idempotency_dir: getEnv("IDEMPOTENCY_DIR", "./data/cache/idempotency"),
  chunk_size: getEnvNum("CHUNK_SIZE", 100),
  idempotency_strategy: getEnv("IDEMPOTENCY_STRATEGY", "skip") as
    | "skip"
    | "overwrite",

  // Processing
  test_limit:
    getEnvNum("TEST_LIMIT", 0) > 0 ? getEnvNum("TEST_LIMIT", 0) : null,
};

export const aiConfig = {
  provider,
  base_url: extraction.base_url,
  extraction_model: config.ai_extraction_model,
  analysis_model: analysis.effective_model,
  analysis_base_url: analysis.base_url,
};

export function validateConfig(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (
    !etherscanKey ||
    etherscanKey.startsWith("Your") ||
    etherscanKey.length < 10
  ) {
    errors.push("ETHERSCAN_API_KEY is required");
  }

  if (config.ai_enabled) {
    const providerUpper = provider.toUpperCase();
    const keyName = providerUpper === "OPENROUTER" ? "OPENROUTER_API_KEY" 
      : providerUpper === "CROF" ? "CROF_API_KEY" 
      : "GEMINI_API_KEY";
    
    if (!config.ai_api_key) {
      errors.push(
        `AI is enabled but ${keyName} is missing - please set ${keyName} environment variable`,
      );
    }
  }

  return { valid: errors.length === 0, errors };
}
