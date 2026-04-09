import { readdir, readFile } from 'fs/promises';
import { join, basename, relative } from 'path';
import { z } from 'zod';
import { logger } from '../lib/logger';
import type { ParsedPOC, ParsedPOCSchema } from '../domain/vulnerability';

// Address regex patterns
const ADDRESS_PATTERNS = [
  // Standard Ethereum address (0x...)
  /0x[a-fA-F0-9]{40}/g,
  // Etherscan/Bscscan address link
  /https?:\/\/(etherscan\.io|bscscan\.com|arbiscan\.io|basescan\.org|polygonscan\.com)\/address\/(0x[a-fA-F0-9]{40})/gi,
  // Raw address with role hint in comments
  /(?:\/\/\s*.*?(?:vulnerable|attacker|attack|helper|target|pool|token|contract).*?)(0x[a-fA-F0-9]{40})/gi,
];

// Chain detection from explorer URLs
const EXPLORER_CHAINS: Record<string, number> = {
  'etherscan.io': 1,
  'sepolia.etherscan.io': 11155111,
  'bscscan.com': 56,
  'testnet.bscscan.com': 97,
  'polygonscan.com': 137,
  'amoy.polygonscan.com': 80002,
  'arbiscan.io': 42161,
  'sepolia.arbiscan.io': 421614,
  'basescan.org': 8453,
  'sepolia.basescan.org': 84532,
  'optimistic.etherscan.io': 10,
  'sepolia-optimistic.etherscan.io': 11155420,
  'snowtrace.io': 43114,
  'testnet.snowtrace.io': 43113,
  'lineascan.build': 59144,
  'sepolia.lineascan.build': 59141,
  'blastscan.io': 81457,
  'sepolia.blastscan.io': 168587773,
};

// Role keywords mapping
const ROLE_KEYWORDS: Record<string, 'vulnerable' | 'attacker' | 'helper'> = {
  'vulnerable': 'vulnerable',
  'target': 'vulnerable',
  'pool': 'vulnerable',
  'vault': 'vulnerable',
  'protocol': 'vulnerable',
  'token': 'helper',
  'attacker': 'attacker',
  'attack': 'attacker',
  'exploit': 'attacker',
  'attacker': 'attacker',
  'helper': 'helper',
  'interface': 'helper',
};

interface RawAddress {
  address: string;
  chain_hint?: string;
  role?: 'vulnerable' | 'attacker' | 'helper' | 'unknown';
  source: string;
}

export class POCParser {
  private parserVersion: string;

  constructor() {
    // In real implementation, get from git
    this.parserVersion = '1.0.0';
  }

  async findPOCFiles(inputDir: string): Promise<string[]> {
    const files: string[] = [];
    
    async function walk(dir: string) {
      const entries = await readdir(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.name.endsWith('.sol') && entry.name.includes('_exp')) {
          files.push(fullPath);
        }
      }
    }
    
    await walk(inputDir);
    return files;
  }

  extractAddresses(code: string): RawAddress[] {
    const addresses: RawAddress[] = [];
    const found = new Set<string>();

    // Extract from comment headers like:
    // // Vulnerable Contract : https://etherscan.io/address/0x...
    // // Attack Contract : https://arbiscan.io/address/0x...
    const commentLines = code.split('\n').filter(line => 
      line.trim().startsWith('//')
    );

    for (const line of commentLines) {
      // Check for explorer URLs with addresses
      const urlMatch = line.match(/https?:\/\/([^\/]+)\/address\/(0x[a-fA-F0-9]{40})/gi);
      if (urlMatch) {
        for (const url of urlMatch) {
          const match = url.match(/https?:\/\/([^\/]+)\/address\/(0x[a-fA-F0-9]{40})/i);
          if (match) {
            const [, explorer, address] = match;
            const addrKey = `${address}-${explorer}`;
            if (!found.has(addrKey)) {
              found.add(addrKey);
              addresses.push({
                address: address.toLowerCase(),
                chain_hint: explorer,
                role: this.detectRole(line),
                source: `comment: ${line.trim().substring(0, 100)}`,
              });
            }
          }
        }
      }
    }

    // Also extract raw 0x addresses from code (less reliable)
    const rawMatches = code.match(/0x[a-fA-F0-9]{40}/g) || [];
    for (const addr of rawMatches) {
      if (!found.has(addr.toLowerCase())) {
        // Skip if it looks like a common placeholder
        if (this.isPlaceholderAddress(addr)) continue;
        
        found.add(addr.toLowerCase());
        addresses.push({
          address: addr.toLowerCase(),
          role: 'unknown',
          source: 'code_match',
        });
      }
    }

    return addresses;
  }

  private detectRole(text: string): 'vulnerable' | 'attacker' | 'helper' | 'unknown' {
    const lower = text.toLowerCase();
    
    for (const [keyword, role] of Object.entries(ROLE_KEYWORDS)) {
      if (lower.includes(keyword)) {
        return role;
      }
    }
    
    return 'unknown';
  }

  private isPlaceholderAddress(address: string): boolean {
    const lower = address.toLowerCase();
    // Common placeholder addresses
    const placeholders = [
      '0x0000000000000000000000000000000000000000', // zero address
      '0x0000000000000000000000000000000000000001', // IEF
      '0x0000000000000000000000000000000000000002', // Chat
      '0x000000000000000000000000000000000000dead', // burner
      '0xdead000000000000000000000000000000000000', // burner
    ];
    return placeholders.includes(lower);
  }

  detectChain(addressOrUrl: string): number | null {
    const lower = addressOrUrl.toLowerCase();
    
    for (const [explorer, chainId] of Object.entries(EXPLORER_CHAINS)) {
      if (lower.includes(explorer)) {
        return chainId;
      }
    }
    
    return null;
  }

  extractTitle(code: string, filePath: string): { title: string; attack_title: string } {
    let title = basename(filePath, '.sol');
    let attack_title = title;

    // Extract from comment headers
    const commentLines = code.split('\n').filter(line => 
      line.trim().startsWith('//')
    );

    for (const line of commentLines) {
      const lower = line.toLowerCase();
      
      // Try to find title
      if (lower.includes('title') || lower.includes('name')) {
        const match = line.match(/\/\/\s*(?:title|name)[:\s]*([^\n]+)/i);
        if (match) {
          title = match[1].trim();
        }
      }
      
      // Try to find attack title
      if (lower.includes('attack') || lower.includes('vulnerability')) {
        const match = line.match(/\/\/\s*(?:attack|vulnerability)[:\s]*([^\n]+)/i);
        if (match) {
          attack_title = match[1].trim();
        }
      }
    }

    // Fallback: clean up filename
    if (title === basename(filePath, '.sol')) {
      title = title.replace(/_exp$/, '').replace(/_/g, ' ');
    }

    return { title, attack_title };
  }

  async parsePOCFile(filePath: string): Promise<ParsedPOC> {
    const code = await readFile(filePath, 'utf-8');
    const { title, attack_title } = this.extractTitle(code, filePath);
    const rawAddresses = this.extractAddresses(code);
    
    // Calculate confidence based on how many addresses were found from reliable sources
    const headerAddresses = rawAddresses.filter(a => a.source.startsWith('comment')).length;
    const totalAddresses = rawAddresses.length;
    const confidence = totalAddresses > 0 
      ? (headerAddresses / totalAddresses) * 0.7 + (totalAddresses > 0 ? 0.3 : 0)
      : 0;

    return {
      id: this.generateId(filePath),
      title,
      attack_title: attack_title || title,
      code,
      raw_addresses: rawAddresses,
      file_path: relative('./', filePath),
      confidence,
    };
  }

  private generateId(filePath: string): string {
    const name = basename(filePath, '.sol');
    return name.replace(/_exp$/, '').toLowerCase().replace(/[^a-z0-9]/g, '_');
  }

  getVersion(): string {
    return this.parserVersion;
  }
}

export function createPOCParser(): POCParser {
  return new POCParser();
}
