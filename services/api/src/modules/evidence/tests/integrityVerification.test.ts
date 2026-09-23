import { describe, it, expect } from 'vitest';
import { computeEvidenceHash, computeEventHash, buildMerkleRoot, CanonicalEvidenceInput } from '@ciperscope/integrity';
import { verifyEvidenceIntegrity, IntegrityVerificationInput } from '../integrityVerification';

function evidence(overrides: Partial<CanonicalEvidenceInput> = {}): CanonicalEvidenceInput {
  return {
    id: 'ev-1', organizationId: 'org-1', caseId: 'case-1', type: 'LOG',
    sha256: 'a'.repeat(64), filename: 'x.log', mimeType: 'text/plain', sizeBytes: 100,
    collectionTime: new Date('2026-01-01T00:00:00Z'),
    ...overrides,
  };
}

function validCustodyEvents() {
  const t = new Date('2026-01-01T00:00:00Z');
  const hash = computeEventHash(null, { action: 'UPLOADED', actorId: 'user-1', description: null, timestamp: t });
  return [{ id: 'e1', eventHash: hash, previousEventId: null, action: 'UPLOADED', actorId: 'user-1', description: null, timestamp: t }];
}

function baseInput(overrides: Partial<IntegrityVerificationInput> = {}): IntegrityVerificationInput {
  return {
    evidence: evidence(),
    custodyEvents: validCustodyEvents(),
    anchor: null,
    batchEvidenceHashes: null,
    ...overrides,
  };
}

describe('verifyEvidenceIntegrity', () => {
  it('INCOMPLETE — valid hash and chain, but never batched (no anchor)', () => {
    const result = verifyEvidenceIntegrity(baseInput());
    expect(result.status).toBe('INCOMPLETE');
    expect(result.chainValid).toBe(true);
    expect(result.merkleValid).toBe('NOT_BATCHED');
    expect(result.evidenceHash).toBe(computeEvidenceHash(evidence()));
  });

  it('INCOMPLETE — no custody events exist at all', () => {
    const result = verifyEvidenceIntegrity(baseInput({ custodyEvents: [] }));
    expect(result.status).toBe('INCOMPLETE');
    expect(result.chainValid).toBe(false); // EMPTY_CHAIN
  });

  it('INVALID — chain of custody was tampered with', () => {
    const tampered = validCustodyEvents();
    tampered[0] = { ...tampered[0], description: 'tampered after the fact' };
    const result = verifyEvidenceIntegrity(baseInput({ custodyEvents: tampered }));
    expect(result.status).toBe('INVALID');
    expect(result.chainValid).toBe(false);
  });

  it('NOT_CONFIGURED — evidence is batched, Merkle root verifies, but no blockchain network is configured', () => {
    const ev = evidence();
    const hash = computeEvidenceHash(ev);
    const otherHash = computeEvidenceHash(evidence({ id: 'ev-2', sha256: 'b'.repeat(64) }));
    const batchHashes = [hash, otherHash];
    const merkleRoot = buildMerkleRoot(batchHashes)!;

    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'NOT_CONFIGURED', merkleRoot, evidenceCount: 2, network: null, transactionId: null, blockNumber: null, anchoredAt: null },
      batchEvidenceHashes: batchHashes,
    }));
    expect(result.status).toBe('NOT_CONFIGURED');
    expect(result.merkleValid).toBe(true);
    expect(result.anchorStatus).toBe('NOT_CONFIGURED');
  });

  it('VALID — batched, Merkle root verifies, and a real blockchain anchor confirmed', () => {
    const ev = evidence();
    const hash = computeEvidenceHash(ev);
    const batchHashes = [hash];
    const merkleRoot = buildMerkleRoot(batchHashes)!;

    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'ANCHORED', merkleRoot, evidenceCount: 1, network: 'TestNet', transactionId: '0xabc123', blockNumber: 42, anchoredAt: new Date() },
      batchEvidenceHashes: batchHashes,
    }));
    expect(result.status).toBe('VALID');
    expect(result.merkleValid).toBe(true);
    expect(result.transactionId).toBe('0xabc123');
  });

  it('INVALID — Merkle root does not reconstruct (tampering / batch corruption)', () => {
    const ev = evidence();
    const hash = computeEvidenceHash(ev);
    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'ANCHORED', merkleRoot: 'not-the-real-root', evidenceCount: 1, network: 'TestNet', transactionId: '0xabc', blockNumber: 1, anchoredAt: new Date() },
      batchEvidenceHashes: [hash],
    }));
    expect(result.status).toBe('INVALID');
    expect(result.merkleValid).toBe(false);
  });

  it('INVALID — this evidence\'s hash is not actually among the batch\'s evidence hashes (membership forged)', () => {
    const otherHash = computeEvidenceHash(evidence({ id: 'ev-99', sha256: 'c'.repeat(64) }));
    const merkleRoot = buildMerkleRoot([otherHash])!;
    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'ANCHORED', merkleRoot, evidenceCount: 1, network: 'TestNet', transactionId: '0xabc', blockNumber: 1, anchoredAt: new Date() },
      batchEvidenceHashes: [otherHash], // does not include our evidence's own hash
    }));
    expect(result.status).toBe('INVALID');
    expect(result.merkleValid).toBe(false);
  });

  it('INCOMPLETE — batched but external anchoring has not completed yet (BATCHED status)', () => {
    const ev = evidence();
    const hash = computeEvidenceHash(ev);
    const merkleRoot = buildMerkleRoot([hash])!;
    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'BATCHED', merkleRoot, evidenceCount: 1, network: null, transactionId: null, blockNumber: null, anchoredAt: null },
      batchEvidenceHashes: [hash],
    }));
    expect(result.status).toBe('INCOMPLETE');
  });

  it('INCOMPLETE — external anchoring attempt FAILED, but this never claims tampering (chain/merkle still verified)', () => {
    const ev = evidence();
    const hash = computeEvidenceHash(ev);
    const merkleRoot = buildMerkleRoot([hash])!;
    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'FAILED', merkleRoot, evidenceCount: 1, network: null, transactionId: null, blockNumber: null, anchoredAt: null },
      batchEvidenceHashes: [hash],
    }));
    expect(result.status).toBe('INCOMPLETE');
    expect(result.merkleValid).toBe(true);
  });

  it('never returns VALID when a required stage was skipped (no batchEvidenceHashes despite an anchor reference)', () => {
    const result = verifyEvidenceIntegrity(baseInput({
      anchor: { status: 'ANCHORED', merkleRoot: 'x', evidenceCount: 1, network: 'TestNet', transactionId: '0xabc', blockNumber: 1, anchoredAt: new Date() },
      batchEvidenceHashes: null,
    }));
    expect(result.status).not.toBe('VALID');
    expect(result.merkleValid).toBe('NOT_BATCHED');
  });
});
