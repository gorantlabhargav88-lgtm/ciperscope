export interface AnchorRequest {
  merkleRoot: string;
  evidenceCount: number;
  organizationId: string;
  batchKey: string;
}

export type AnchorOutcome =
  | { status: 'ANCHORED'; network: string; transactionId: string; blockNumber: number | null; contractAddress?: string | null; anchoredAt: Date }
  | { status: 'NOT_CONFIGURED'; reason?: string }
  | { status: 'FAILED'; errorMessage: string };

/**
 * A provider only ever submits a `merkleRoot` (and bookkeeping metadata) —
 * never raw evidence content, filenames, or any other private data. See
 * NullBlockchainAnchorProvider for the always-available default; a real
 * network provider is only ever constructed when genuine credentials/network
 * configuration exist (see BlockchainAnchorConfig.ts) — never invented.
 */
export interface IBlockchainAnchorProvider {
  readonly name: string;
  anchorMerkleRoot(request: AnchorRequest): Promise<AnchorOutcome>;
  getAnchorStatus(transactionId: string): Promise<AnchorOutcome>;
}
