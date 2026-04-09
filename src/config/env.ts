import { CHAIN_CONFIG, type ChainId } from '../domain/chain';

export type ApiTier = 'free' | 'paid';

export interface Config {
  // AI (optional)
  openrouter_api_key: string;
  ai_model: string;
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
  idempotency_strategy: 'skip' | 'overwrite';
  
  // Processing
  test_limit: number | null;
}

function getEnv(key: string, defaultValue = ''): string {
  return process.env[key] ?? defaultValue;
}

function getEnvBool(key: string, defaultValue = false): boolean {
  const val = process.env[key]?.toLowerCase();
  if (val === 'true' || val === '1') return true;
  if (val === 'false' || val === '0') return false;
  return defaultValue;
}

function getEnvNum(key: string, defaultValue: number): number {
  const val = parseInt(process.env[key] ?? '', 10);
  return isNaN(val) ? defaultValue : val;
}

const etherscanKey = getEnv('ETHERSCAN_API_KEY', '');

export const config: Config = {
  // AI
  openrouter_api_key: getEnv('OPENROUTER_API_KEY', ''),
  ai_model: getEnv('AI_MODEL', 'openai/gpt-4o-mini'),
  ai_enabled: getEnvBool('AI_ENABLED', false),
  ai_temperature: getEnvNum('AI_TEMPERATURE', 0.3),
  
  // Etherscan
  etherscan_api_key: etherscanKey,
  etherscan_tier: (getEnv('ETHERSCAN_TIER', 'free') as ApiTier),
  
  // Pipeline
  cache_enabled: getEnvBool('CACHE_ENABLED', true),
  cache_ttl_seconds: getEnvNum('CACHE_TTL_SECONDS', 86400 * 7),
  rate_limit_rps: getEnvNum('RATE_LIMIT_RPS', 5),
  
  // Concurrency
  fetch_parallel: getEnvNum('FETCH_PARALLEL', 5),
  ai_parallel: getEnvNum('AI_PARALLEL', 1),
  ai_delay_ms: getEnvNum('AI_DELAY_MS', 1000),
  
  // Output
  input_dir: getEnv('INPUT_DIR', './data/input/DeFiHackLabs/src/test'),
  output_dir: getEnv('OUTPUT_DIR', './data/output'),
  cache_dir: getEnv('CACHE_DIR', './data/cache'),
  idempotency_dir: getEnv('IDEMPOTENCY_DIR', './data/cache/idempotency'),
  chunk_size: getEnvNum('CHUNK_SIZE', 100),
  idempotency_strategy: (getEnv('IDEMPOTENCY_STRATEGY', 'skip') as 'skip' | 'overwrite'),
  
  // Processing
  test_limit: getEnvNum('TEST_LIMIT', 0) > 0 ? getEnvNum('TEST_LIMIT', 0) : null,
};

export function validateConfig(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!etherscanKey || etherscanKey.startsWith('Your') || etherscanKey.length < 10) {
    errors.push('ETHERSCAN_API_KEY is required. Get one from https://etherscan.io/apis');
  }
  
  if (config.ai_enabled && !config.openrouter_api_key) {
    errors.push('OPENROUTER_API_KEY is required when AI_ENABLED is true');
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
}
