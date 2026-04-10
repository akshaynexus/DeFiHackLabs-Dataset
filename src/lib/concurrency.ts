export async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }

  const safeConcurrency = Math.max(1, Math.min(concurrency, items.length));
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  async function runWorker() {
    while (true) {
      const index = nextIndex++;
      if (index >= items.length) {
        return;
      }
      const item = items[index];
      if (item === undefined) {
        return;
      }
      results[index] = await worker(item, index);
    }
  }

  await Promise.all(
    Array.from({ length: safeConcurrency }, () => runWorker()),
  );

  return results;
}

export class Semaphore {
  private readonly maxPermits: number;
  private permits: number;
  private queue: Array<() => void> = [];

  constructor(permits: number) {
    this.maxPermits = Math.max(1, permits);
    this.permits = this.maxPermits;
  }

  async use<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  getMaxPermits(): number {
    return this.maxPermits;
  }

  private async acquire(): Promise<void> {
    if (this.permits > 0) {
      this.permits--;
      return;
    }

    await new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  private release() {
    const next = this.queue.shift();
    if (next) {
      next();
      return;
    }
    this.permits = Math.min(this.permits + 1, this.maxPermits);
  }
}

export class MinIntervalGate {
  private readonly minIntervalMs: number;
  private nextReadyAt = 0;

  constructor(minIntervalMs: number) {
    this.minIntervalMs = Math.max(0, minIntervalMs);
  }

  async waitTurn(): Promise<void> {
    if (this.minIntervalMs === 0) {
      return;
    }

    const now = Date.now();
    const readyAt = Math.max(this.nextReadyAt, now);
    const waitMs = readyAt - now;

    this.nextReadyAt = readyAt + this.minIntervalMs;

    if (waitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, waitMs));
    }
  }
}
