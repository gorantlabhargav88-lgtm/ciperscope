import { IBlockchainProvider, AnchorOutcome, VerifyAnchorRequest, VerifyAnchorResult } from './types';

/**
 * Used whenever blockchain anchoring is disabled (BLOCKCHAIN_ENABLED=false) or
 * unconfigured (missing RPC URL, private key, or contract address).
 * Returns honest NOT_CONFIGURED — never fabricated transaction IDs, demo hashes, or false confirmations.
 */
export class NullBlockchainProvider implements IBlockchainProvider {
  public readonly name = 'null';

  constructor(private readonly reason: string = 'Blockchain integration is disabled or not configured') {}

  public async anchorMerkleRoot(): Promise<AnchorOutcome> {
    return { status: 'NOT_CONFIGURED', reason: this.reason };
  }

  public async verifyAnchor(request: VerifyAnchorRequest): Promise<VerifyAnchorResult> {
    return {
      verified: false,
      network: 'none',
      contractAddress: null,
      transactionHash: request.transactionId ?? null,
      anchoredMerkleRoot: null,
      localMerkleRoot: request.merkleRoot,
      blockNumber: null,
      timestamp: null,
      reason: this.reason,
    };
  }

  public async getAnchorStatus(): Promise<AnchorOutcome> {
    return { status: 'NOT_CONFIGURED', reason: this.reason };
  }
}
