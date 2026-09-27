import { IBlockchainAnchorProvider } from './providers/IBlockchainAnchorProvider';
import { BlockchainProviderConfig } from '@ciperscope/providers';

/**
 * Returns the configured blockchain provider (EvmBlockchainProvider when
 * BLOCKCHAIN_ENABLED=true with valid RPC URL and credentials, or
 * NullBlockchainProvider when unconfigured/disabled).
 */
export class BlockchainAnchorConfig {
  public static getProvider(): IBlockchainAnchorProvider {
    return BlockchainProviderConfig.getProvider();
  }
}
