import { IBlockchainAnchorProvider } from './providers/IBlockchainAnchorProvider';
import { NullBlockchainAnchorProvider } from './providers/NullBlockchainAnchorProvider';

/**
 * No real blockchain network/credentials exist anywhere in this
 * repository's configuration (@ciperscope/config) — confirmed by Phase M
 * discovery. Per the phase's explicit instruction, no RPC URL, contract
 * address, network name, or credential is invented here. This factory is
 * the intended extension point: a real provider class (constructed from
 * genuine config, e.g. a future `BLOCKCHAIN_ANCHOR_NETWORK`/
 * `BLOCKCHAIN_ANCHOR_RPC_URL` env pair) would be selected here exactly the
 * way `CtiConfig`/`DomainIntelConfig` select a real provider only when
 * real credentials are present — until then, this always returns the Null
 * provider, and every anchor honestly reports NOT_CONFIGURED.
 */
export class BlockchainAnchorConfig {
  public static getProvider(): IBlockchainAnchorProvider {
    return new NullBlockchainAnchorProvider();
  }
}
