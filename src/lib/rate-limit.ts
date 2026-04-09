export interface RateLimitConfig {
  rps: number;
  maxBurst?: number;
}

export class TokenBucket {
  private tokens: number;
  private maxTokens: number;
  private refillRate: number;
  private lastRefill: number;
  private readonly refillIntervalMs: number;

  constructor(config: RateLimitConfig) {
    this.maxTokens = config.maxBurst ?? config.rps;
    this.tokens = this.maxTokens;
    this.refillRate = config.rps;
    this.refillIntervalMs = 1000 / config.rps;
    this.lastRefill = Date.now();
  }

  private refill() {
    const now = Date.now();
    const elapsed = now - this.lastRefill;
    const tokensToAdd = Math.floor(elapsed / this.refillIntervalMs);

    if (tokensToAdd > 0) {
      this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd);
      this.lastRefill = now;
    }
  }

  async acquire(tokens = 1): Promise<void> {
    this.refill();

    while (this.tokens < tokens) {
      const waitTime =
        (this.refillIntervalMs * (tokens - this.tokens)) / this.refillRate;
      await new Promise((resolve) => setTimeout(resolve, waitTime));
      this.refill();
    }

    this.tokens -= tokens;
  }

  tryAcquire(tokens = 1): boolean {
    this.refill();
    if (this.tokens >= tokens) {
      this.tokens -= tokens;
      return true;
    }
    return false;
  }

  getAvailableTokens(): number {
    this.refill();
    return this.tokens;
  }
}

export class MultiRateLimiter {
  private limiters: Map<string, TokenBucket> = new Map();
  private defaultConfig: RateLimitConfig;

  constructor(defaultConfig: RateLimitConfig) {
    this.defaultConfig = defaultConfig;
  }

  getLimiter(key: string): TokenBucket {
    if (!this.limiters.has(key)) {
      this.limiters.set(key, new TokenBucket(this.defaultConfig));
    }
    return this.limiters.get(key)!;
  }

  async acquire(key: string, tokens = 1): Promise<void> {
    return this.getLimiter(key).acquire(tokens);
  }

  tryAcquire(key: string, tokens = 1): boolean {
    return this.getLimiter(key).tryAcquire(tokens);
  }
}

export const defaultRateLimiter = new MultiRateLimiter({
  rps: 5,
  maxBurst: 10,
});
