import { env } from '@ciperscope/config';
import { IBlockchainProvider } from './types';
import { NullBlockchainProvider } from './NullBlockchainProvider';
import { EvmBlockchainProvider } from './EvmBlockchainProvider';

export class BlockchainProviderConfig {
  private static cachedProvider: IBlockchainProvider | null = null;

  public static getProvider(): IBlockchainProvider {
    const isEnabled = env.BLOCKCHAIN_ENABLED === 'true';
    const rpcUrl = env.BLOCKCHAIN_RPC_URL;

    if (!isEnabled || !rpcUrl) {
      const reason = !isEnabled
        ? 'Blockchain integration is disabled (BLOCKCHAIN_ENABLED != true)'
        : 'Blockchain RPC URL is not configured (BLOCKCHAIN_RPC_URL missing)';
      return new NullBlockchainProvider(reason);
    }

    return new EvmBlockchainProvider({
      rpcUrl,
      network: env.BLOCKCHAIN_NETWORK || 'sepolia',
      chainId: env.BLOCKCHAIN_CHAIN_ID,
      contractAddress: env.BLOCKCHAIN_CONTRACT_ADDRESS,
      privateKey: env.BLOCKCHAIN_PRIVATE_KEY,
    });
  }

  public static resetCache(): void {
    this.cachedProvider = null;
  }
}
