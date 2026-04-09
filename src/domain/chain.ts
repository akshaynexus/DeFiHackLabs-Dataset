import { z } from 'zod';

export const CHAIN_CONFIG = {
  1: { name: 'Ethereum', explorer: 'https://etherscan.io', api_url: 'https://api.etherscan.io/v2/api' },
  11155111: { name: 'Sepolia', explorer: 'https://sepolia.etherscan.io', api_url: 'https://api.etherscan.io/v2/api' },
  56: { name: 'BSC', explorer: 'https://bscscan.com', api_url: 'https://api.bscscan.com/api' },
  97: { name: 'BSC Testnet', explorer: 'https://testnet.bscscan.com', api_url: 'https://api-testnet.bscscan.com/api' },
  137: { name: 'Polygon', explorer: 'https://polygonscan.com', api_url: 'https://api.polygonscan.com/api' },
  80002: { name: 'Polygon Amoy', explorer: 'https://amoy.polygonscan.com', api_url: 'https://api-amoy.polygonscan.com/api' },
  42161: { name: 'Arbitrum One', explorer: 'https://arbiscan.io', api_url: 'https://api.arbiscan.io/api' },
  421614: { name: 'Arbitrum Sepolia', explorer: 'https://sepolia.arbiscan.io', api_url: 'https://api-sepolia.arbiscan.io/api' },
  8453: { name: 'Base', explorer: 'https://basescan.org', api_url: 'https://api.basescan.org/api' },
  84532: { name: 'Base Sepolia', explorer: 'https://sepolia.basescan.org', api_url: 'https://api-sepolia.basescan.org/api' },
  10: { name: 'Optimism', explorer: 'https://optimistic.etherscan.io', api_url: 'https://api-optimistic.etherscan.io/api' },
  11155420: { name: 'Optimism Sepolia', explorer: 'https://sepolia-optimistic.etherscan.io', api_url: 'https://api-sepolia-optimistic.etherscan.io/api' },
  43114: { name: 'Avalanche', explorer: 'https://snowtrace.io', api_url: 'https://api.snowtrace.io/api' },
  43113: { name: 'Avalanche Fuji', explorer: 'https://testnet.snowtrace.io', api_url: 'https://api-testnet.snowtrace.io/api' },
  59144: { name: 'Linea', explorer: 'https://lineascan.build', api_url: 'https://api.lineascan.build/api' },
  59141: { name: 'Linea Sepolia', explorer: 'https://sepolia.lineascan.build', api_url: 'https://api-sepolia.lineascan.build/api' },
  81457: { name: 'Blast', explorer: 'https://blastscan.io', api_url: 'https://api.blastscan.io/api' },
  168587773: { name: 'Blast Sepolia', explorer: 'https://sepolia.blastscan.io', api_url: 'https://api-sepolia.blastscan.io/api' },
  100: { name: 'Gnosis', explorer: 'https://gnosisscan.io', api_url: 'https://api.gnosisscan.io/api' },
  5000: { name: 'Mantle', explorer: 'https://mantlescan.xyz', api_url: 'https://api.mantlescan.xyz/api' },
  5003: { name: 'Mantle Sepolia', explorer: 'https://testnet.mantlescan.xyz', api_url: 'https://api-testnet.mantlescan.xyz/api' },
  204: { name: 'opBNB', explorer: 'https://opbnbscan.com', api_url: 'https://api.opbnbscan.com/api' },
  5611: { name: 'opBNB Testnet', explorer: 'https://opbnbscan.com/testnet', api_url: 'https://api-opbnb-testnet.bscscan.com/api' },
  534352: { name: 'Scroll', explorer: 'https://scrollscan.com', api_url: 'https://api.scrollscan.com/api' },
  534351: { name: 'Scroll Sepolia', explorer: 'https://sepolia.scrollscan.com', api_url: 'https://api-sepolia.scrollscan.com/api' },
  167000: { name: 'Taiko', explorer: 'https://taikoscan.io', api_url: 'https://api.taikoscan.io/api' },
  167013: { name: 'Taiko Hoodi', explorer: 'https://hoodi.taikoscan.io', api_url: 'https://api.hoodi.taikoscan.io/api' },
  1328: { name: 'Sei', explorer: 'https://seistats.com', api_url: 'https://api.seistats.com/api' },
  1329: { name: 'Sei Devnet', explorer: 'https://seitrace.com', api_url: 'https://api.seitrace.com/api' },
} as const;

export type ChainId = keyof typeof CHAIN_CONFIG;
export type ChainName = typeof CHAIN_CONFIG[ChainId]['name'];

export function getChainConfig(chainId: number): { name: string; explorer: string; api_url: string } | null {
  return CHAIN_CONFIG[chainId as ChainId] ?? null;
}

export function getChainIdFromExplorer(explorerUrl: string): number | null {
  for (const [id, config] of Object.entries(CHAIN_CONFIG)) {
    if (explorerUrl.includes(config.explorer.replace('https://', ''))) {
      return Number(id);
    }
  }
  return null;
}
