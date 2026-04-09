export interface RetryOptions {
  maxAttempts: number;
  initialDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  retryableErrors?: string[];
}

const defaultRetryOptions: RetryOptions = {
  maxAttempts: 3,
  initialDelayMs: 1000,
  maxDelayMs: 10000,
  backoffMultiplier: 2,
};

export async function retry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {},
): Promise<T> {
  const opts = { ...defaultRetryOptions, ...options };
  let lastError: Error | undefined;
  let delay = opts.initialDelayMs;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === opts.maxAttempts) {
        break;
      }

      // Check if error is retryable
      const errorMessage = lastError.message.toLowerCase();
      const isRetryable =
        opts.retryableErrors?.some((e) =>
          errorMessage.includes(e.toLowerCase()),
        ) ?? true; // Default: retry all

      if (!isRetryable) {
        throw lastError;
      }

      // Wait with exponential backoff
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * opts.backoffMultiplier, opts.maxDelayMs);
    }
  }

  throw lastError;
}

export interface AsyncRetryOptions<T> extends RetryOptions {
  shouldRetry?: (error: Error, attempt: number) => boolean | Promise<boolean>;
  onRetry?: (error: Error, attempt: number) => void | Promise<void>;
}

export async function asyncRetry<T>(
  fn: () => Promise<T>,
  options: Partial<AsyncRetryOptions<T>> = {},
): Promise<T> {
  const opts: AsyncRetryOptions<T> = {
    ...defaultRetryOptions,
    shouldRetry: () => true,
    ...options,
  };

  let lastError: Error | undefined;
  let delay = opts.initialDelayMs;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === opts.maxAttempts) {
        break;
      }

      const shouldRetry = await opts.shouldRetry!(lastError, attempt);
      if (!shouldRetry) {
        throw lastError;
      }

      if (opts.onRetry) {
        await opts.onRetry(lastError, attempt);
      }

      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * opts.backoffMultiplier, opts.maxDelayMs);
    }
  }

  throw lastError;
}
