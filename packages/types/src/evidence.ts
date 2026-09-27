/**
 * Evidence & chain-of-custody contracts.
 * Backend mapping: services/api/src/modules/case/case.routes.ts
 * (`/cases/:caseId/evidence`, `/cases/:caseId/evidence/:evidenceId`,
 * `/cases/:caseId/evidence/:evidenceId/custody`) returns raw Prisma
 * Evidence / ChainOfCustodyEvent rows — field names kept as-is.
 */

export type EvidenceType =
  | 'RAW_EMAIL'
  | 'HEADER'
  | 'ATTACHMENT'
  | 'URL'
  | 'IP'
  | 'DOMAIN'
  | 'SCREENSHOT'
  | 'REPORT'
  | 'LOG'
  | 'OTHER';

export type EvidenceStatus = 'ACTIVE' | 'ARCHIVED' | 'DELETED';

export type CustodyAction =
  | 'COLLECTED'
  | 'UPLOADED'
  | 'HASHED'
  | 'ANALYZED'
  | 'EXPORTED'
  | 'VERIFIED'
  | 'BLOCKCHAIN_ANCHORED'
  | 'ACCESSED';

export interface Evidence {
  id: string;
  caseId: string;
  type: EvidenceType;
  filename: string | null;
  mimeType: string | null;
  sizeBytes: number | null;
  sha256: string;
  status: EvidenceStatus;
  collectionTime: string;
  collectedById: string | null;
}

/** Org-wide evidence vault row — same shape as Evidence but without a guaranteed caseId scope (returned by GET /evidence, /evidence/:id). */
export interface EvidenceVaultItem extends Evidence {
  sourceSystem: string | null;
  relatedEmailId?: string | null;
}

export type IntegrityOverallStatus = 'VALID' | 'INVALID' | 'INCOMPLETE' | 'NOT_CONFIGURED';

/**
 * Response shape of GET /evidence/:evidenceId/integrity (services/api/src/
 * modules/evidence/integrityVerification.ts). Real, cryptographic
 * verification of the evidence hash, chain-of-custody linkage, and — when
 * the evidence has been included in a notarization batch — the Merkle root
 * and external blockchain anchor. `NOT_CONFIGURED` is its own honest
 * outcome (everything verifiable was verified; no blockchain network is
 * configured) — never conflated with VALID or INVALID.
 */
export interface EvidenceIntegrity {
  status: IntegrityOverallStatus;
  evidenceHash: string;
  chainValid: boolean;
  chainReason: string | null;
  merkleValid: boolean | 'NOT_BATCHED';
  anchorStatus: string;
  network: string | null;
  transactionId: string | null;
  contractAddress?: string | null;
  blockNumber: number | null;
  anchoredAt: string | null;
  reason: string;
  verifiedAt: string;
}

export type BlockchainAnchorStatus =
  | 'HASHED'
  | 'BATCHED'
  | 'ANCHORED'
  | 'NOT_CONFIGURED'
  | 'FAILED';

export interface BlockchainAnchorItem {
  id: string;
  organizationId: string;
  batchKey: string;
  merkleRoot: string;
  evidenceCount: number;
  hashAlgorithm: string;
  status: BlockchainAnchorStatus;
  network: string | null;
  transactionId: string | null;
  blockNumber: number | null;
  errorDetails: string | null;
  anchoredAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BlockchainAnchorVerification {
  verified: boolean;
  transactionHash: string | null;
  network: string;
  contractAddress: string | null;
  anchoredMerkleRoot: string | null;
  localMerkleRoot: string;
  reconstructedMerkleRoot: string | null;
  localMerkleMatches: boolean;
  blockNumber: number | null;
  anchoredAt: string | null;
  anchorStatus: string;
  evidenceCount: number;
  reason?: string;
  verifiedAt: string;
}

export interface ChainOfCustodyActor {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
}

export interface ChainOfCustodyEntry {
  id: string;
  action: CustodyAction;
  actorId: string | null;
  /** Server-side actor enrichment — see case.routes.ts's custody endpoint. Null when actorId is null or the user is no longer a member of the org. */
  actor: ChainOfCustodyActor | null;
  description: string | null;
  timestamp: string;
  /**
   * FK to the prior event in the append-only custody linked list
   * (ChainOfCustodyEvent.previousEventId). The backend does not resolve
   * this to the previous event's action — do that client-side by looking
   * up this id within the same fetched list (see
   * apps/web/src/components/evidence/ChainOfCustody.tsx). Null for the
   * first event.
   */
  previousEventId: string | null;
}
