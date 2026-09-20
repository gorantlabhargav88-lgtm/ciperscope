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

/**
 * Real blockchain anchoring is not implemented in CiperScope today — the
 * `BlockchainAnchor` Prisma model and `BLOCKCHAIN_ANCHORED` custody action
 * exist, but only as schema plus one demo seed row; no code path ever
 * creates a real anchor (see CIPERSCOPE_NEXT_PHASE_AUDIT.md). This type
 * makes that limitation impossible to silently forget: `blockchainAnchored`
 * is always `false`.
 */
export interface EvidenceIntegrity {
  sha256: string;
  blockchainAnchored: false;
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
