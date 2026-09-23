import { IBlockchainAnchorProvider, AnchorOutcome } from './IBlockchainAnchorProvider';

/**
 * Used whenever no real blockchain network/credentials are configured
 * (the default in this repository — see BlockchainAnchorConfig.ts). Always
 * honest NOT_CONFIGURED, never a fabricated transaction ID/network/block
 * number. The batch/Merkle/hash work above this provider is still real and
 * persisted — only the external anchoring step is skipped.
 */
export class NullBlockchainAnchorProvider implements IBlockchainAnchorProvider {
  public readonly name = 'null';

  public async anchorMerkleRoot(): Promise<AnchorOutcome> {
    return { status: 'NOT_CONFIGURED' };
  }

  public async getAnchorStatus(): Promise<AnchorOutcome> {
    return { status: 'NOT_CONFIGURED' };
  }
}
