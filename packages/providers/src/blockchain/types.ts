export interface AnchorRequest {
  merkleRoot: string;
  evidenceCount: number;
  organizationId: string;
  batchKey: string;
}

export type AnchorOutcome =
  | {
      status: 'ANCHORED';
      network: string;
      transactionId: string;
      blockNumber: number | null;
      contractAddress: string | null;
      anchoredAt: Date;
    }
  | { status: 'NOT_CONFIGURED'; reason?: string }
  | { status: 'FAILED'; errorMessage: string };

export interface VerifyAnchorRequest {
  batchKey: string;
  merkleRoot: string;
  transactionId?: string | null;
}

export interface VerifyAnchorResult {
  verified: boolean;
  network: string;
  contractAddress: string | null;
  transactionHash: string | null;
  anchoredMerkleRoot: string | null;
  localMerkleRoot: string;
  blockNumber: number | null;
  timestamp: Date | null;
  reason?: string;
}

export interface IBlockchainProvider {
  readonly name: string;
  anchorMerkleRoot(request: AnchorRequest): Promise<AnchorOutcome>;
  verifyAnchor(request: VerifyAnchorRequest): Promise<VerifyAnchorResult>;
  getAnchorStatus(transactionId: string): Promise<AnchorOutcome>;
}
