import { basename, join } from 'path';
import { mkdir, readFile, writeFile, stat } from 'fs/promises';

export interface CacheOptions {
  cacheDir: string;
  ttlSeconds?: number;
}

export interface CacheEntry<T> {
  data: T;
  cachedAt: string;
  expiresAt?: string;
}

export class FileCache {
  private cacheDir: string;
  private ttlMs: number | undefined;

  constructor(options: CacheOptions) {
    this.cacheDir = options.cacheDir;
    this.ttlMs = options.ttlSeconds ? options.ttlSeconds * 1000 : undefined;
  }

  private getCachePath(key: string): string {
    // Simple hash-based filename
    const hash = Array.from(key).reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) | 0, 0);
    return join(this.cacheDir, `${Math.abs(hash)}.json`);
  }

  async get<T>(key: string): Promise<T | null> {
    const path = this.getCachePath(key);
    
    try {
      const content = await readFile(path, 'utf-8');
      const entry: CacheEntry<T> = JSON.parse(content);
      
      // Check expiration
      if (this.ttlMs && entry.expiresAt) {
        if (new Date(entry.expiresAt) < new Date()) {
          return null;
        }
      }
      
      return entry.data;
    } catch {
      return null;
    }
  }

  async set<T>(key: string, data: T): Promise<void> {
    const path = this.getCachePath(key);
    const now = new Date();
    
    const entry: CacheEntry<T> = {
      data,
      cachedAt: now.toISOString(),
      expiresAt: this.ttlMs ? new Date(now.getTime() + this.ttlMs).toISOString() : undefined,
    };

    await mkdir(this.cacheDir, { recursive: true });
    await writeFile(path, JSON.stringify(entry, null, 2), 'utf-8');
  }

  async has(key: string): Promise<boolean> {
    const data = await this.get(key);
    return data !== null;
  }

  async delete(key: string): Promise<void> {
    const path = this.getCachePath(key);
    try {
      const { unlink } = await import('fs/promises');
      await unlink(path);
    } catch {
      // Ignore if doesn't exist
    }
  }

  async clear(): Promise<void> {
    try {
      const { readdir, unlink } = await import('fs/promises');
      const files = await readdir(this.cacheDir);
      await Promise.all(files.map(f => unlink(join(this.cacheDir, f))));
    } catch {
      // Ignore if directory doesn't exist
    }
  }

  async getStats(): Promise<{ size: number; oldest?: string; newest?: string }> {
    try {
      const { readdir } = await import('fs/promises');
      const files = await readdir(this.cacheDir);
      
      let oldest: string | undefined;
      let newest: string | undefined;

      for (const file of files) {
        const path = join(this.cacheDir, file);
        const content = await readFile(path, 'utf-8');
        const entry = JSON.parse(content);
        
        if (!oldest || entry.cachedAt < oldest) oldest = entry.cachedAt;
        if (!newest || entry.cachedAt > newest) newest = entry.cachedAt;
      }

      return { size: files.length, oldest, newest };
    } catch {
      return { size: 0 };
    }
  }
}
