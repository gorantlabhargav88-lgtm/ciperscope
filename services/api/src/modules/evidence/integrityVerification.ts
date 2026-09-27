import { computeEvidenceHash, buildMerkleRoot, verifyCustodyChain, CanonicalEvidenceInput, CustodyChainLink } from '@ciperscope/integrity';

export type IntegrityOverallStatus = 'VALID' | 'INVALID' | 'INCOMPLETE' | 'NOT_CONFIGURED';

export interface IntegrityVerificationInput {
  evidence: CanonicalEvidenceInput;
  // Every ChainOfCustodyEvent row for this evidence, any order — the
  // verifier walks the real previousEventId linkage itself.
  custodyEvents: CustodyChainLink[];
  anchor: {
    status: string;
    merkleRoot: string;
    evidenceCount: number;
    network: string | null;
    transactionId: string | null;
    blockNumber: number | null;
    anchoredAt: Date | null;
    contractAddress?: string | null;
  } | null;
  // Present only when `anchor` is non-null: every evidence hash in that
  // batch, freshly recomputed (never read from storage) in the exact
  // order recorded in BlockchainAnchor.evidenceIds — required to
  // reconstruct and verify the Merkle root, not just trust it.
  batchEvidenceHashes: string[] | null;
}

export interface IntegrityVerificationResult {
  status: IntegrityOverallStatus;
  evidenceHash: string;
  chainValid: boolean;
  chainReason: string | null;
  // 'NOT_BATCHED' when this evidence hasn't been included in any anchor
  // yet — never a fabricated true/false for a stage that didn't run.
  merkleValid: boolean | 'NOT_BATCHED';
  anchorStatus: string; // BlockchainAnchorStatus value, or 'NOT_BATCHED'
  network: string | null;
  transactionId: string | null;
  contractAddress: string | null;
  blockNumber: number | null;
  anchoredAt: Date | null;
  reason: string;
  verifiedAt: string;
}

/**
 * Pure verification function — every value it needs is passed in already
 * fetched (see GET /evidence/:evidenceId/integrity for the DB reads). Never
 * returns VALID if a required stage (hash, chain, or — once a batch
 * exists — Merkle reconstruction) was skipped; NOT_CONFIGURED is its own
 * honest outcome (batching/hashing genuinely verified, external
 * blockchain confirmation genuinely absent), never conflated with either
 * VALID or INVALID.
 */
export function verifyEvidenceIntegrity(input: IntegrityVerificationInput): IntegrityVerificationResult {
  const evidenceHash = computeEvidenceHash(input.evidence);
  const chainResult = verifyCustodyChain(input.custodyEvents);
  const chainValid = chainResult.valid;
  const chainReason = chainResult.valid ? null : chainResult.reason;
  const chainIsEmpty = !chainValid && chainReason === 'EMPTY_CHAIN';

  let merkleValid: boolean | 'NOT_BATCHED' = 'NOT_BATCHED';
  let anchorStatus = 'NOT_BATCHED';
  // True only when an anchor reference exists but the data needed to
  // actually verify it (batchEvidenceHashes) was not supplied — this must
  // never silently fall through to VALID, since the Merkle stage was
  // skipped, not passed.
  let anchorVerificationSkipped = false;

  if (input.anchor) {
    anchorStatus = input.anchor.status;
    if (input.batchEvidenceHashes) {
      const recomputedRoot = buildMerkleRoot(input.batchEvidenceHashes);
      const includesThisEvidence = input.batchEvidenceHashes.includes(evidenceHash);
      merkleValid = includesThisEvidence && recomputedRoot === input.anchor.merkleRoot;
    } else {
      anchorVerificationSkipped = true;
    }
  }

  let status: IntegrityOverallStatus;
  let reason: string;

  if (!chainValid && !chainIsEmpty) {
    status = 'INVALID';
    reason = `Chain of custody verification failed: ${chainReason}`;
  } else if (merkleValid === false) {
    status = 'INVALID';
    reason = 'Merkle root reconstruction did not match the anchored batch — evidence or batch membership may have been tampered with.';
  } else if (chainIsEmpty) {
    status = 'INCOMPLETE';
    reason = 'No chain-of-custody events exist for this evidence yet.';
  } else if (anchorVerificationSkipped) {
    status = 'INCOMPLETE';
    reason = 'Evidence is linked to a notarization batch, but the data required to verify that batch\'s Merkle root was not available.';
  } else if (!input.anchor) {
    status = 'INCOMPLETE';
    reason = 'Evidence hash and custody chain are valid; this evidence has not yet been included in a notarization batch.';
  } else if (anchorStatus === 'BATCHED' || anchorStatus === 'FAILED') {
    status = 'INCOMPLETE';
    reason = `Evidence is batched (Merkle root verified) but external anchoring has not completed (status: ${anchorStatus}).`;
  } else if (anchorStatus === 'NOT_CONFIGURED') {
    status = 'NOT_CONFIGURED';
    reason = 'Evidence hash, custody chain, and Merkle batch are all verified. No blockchain network is configured, so external anchoring was honestly skipped.';
  } else {
    // ANCHORED, and merkleValid === true (the only other way to reach here)
    status = 'VALID';
    reason = 'Evidence hash, custody chain, Merkle batch, and external blockchain anchor are all verified.';
  }

  return {
    status,
    evidenceHash,
    chainValid,
    chainReason,
    merkleValid,
    anchorStatus,
    network: input.anchor?.network ?? null,
    transactionId: input.anchor?.transactionId ?? null,
    contractAddress: input.anchor?.contractAddress ?? null,
    blockNumber: input.anchor?.blockNumber ?? null,
    anchoredAt: input.anchor?.anchoredAt ?? null,
    reason,
    verifiedAt: new Date().toISOString(),
  };
}
