import { describe, it, expect } from 'vitest';
import { canonicalizeEvidence, computeEvidenceHash, sha256Hex, CanonicalEvidenceInput } from '../CanonicalHash';

function baseEvidence(overrides: Partial<CanonicalEvidenceInput> = {}): CanonicalEvidenceInput {
  return {
    id: 'ev-1',
    organizationId: 'org-1',
    caseId: 'case-1',
    type: 'LOG',
    sha256: 'a'.repeat(64),
    filename: 'notes.log',
    mimeType: 'text/plain',
    sizeBytes: 1024,
    collectionTime: new Date('2026-01-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('computeEvidenceHash', () => {
  it('identical evidence produces an identical hash', () => {
    expect(computeEvidenceHash(baseEvidence())).toBe(computeEvidenceHash(baseEvidence()));
  });

  it('the hash is a real SHA-256 (64 lowercase hex chars)', () => {
    expect(computeEvidenceHash(baseEvidence())).toMatch(/^[a-f0-9]{64}$/);
  });

  it('field ordering in the JS object does not change the hash — the canonical key order is fixed internally', () => {
    const a: CanonicalEvidenceInput = baseEvidence();
    // Same data, but constructed with a different property assignment order.
    const b: CanonicalEvidenceInput = {
      collectionTime: a.collectionTime,
      sizeBytes: a.sizeBytes,
      mimeType: a.mimeType,
      filename: a.filename,
      sha256: a.sha256,
      type: a.type,
      caseId: a.caseId,
      organizationId: a.organizationId,
      id: a.id,
    };
    expect(computeEvidenceHash(a)).toBe(computeEvidenceHash(b));
  });

  it('mutating an integrity-relevant field (sha256) changes the hash', () => {
    const a = computeEvidenceHash(baseEvidence());
    const b = computeEvidenceHash(baseEvidence({ sha256: 'b'.repeat(64) }));
    expect(a).not.toBe(b);
  });

  it('mutating id, organizationId, caseId, type, filename, mimeType, sizeBytes, or collectionTime each changes the hash', () => {
    const base = computeEvidenceHash(baseEvidence());
    expect(computeEvidenceHash(baseEvidence({ id: 'ev-2' }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ organizationId: 'org-2' }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ caseId: 'case-2' }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ type: 'ATTACHMENT' }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ filename: 'other.log' }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ mimeType: 'application/json' }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ sizeBytes: 2048 }))).not.toBe(base);
    expect(computeEvidenceHash(baseEvidence({ collectionTime: new Date('2027-01-01T00:00:00.000Z') }))).not.toBe(base);
  });

  it('null and undefined-equivalent fields canonicalize deterministically (never throws, never produces different hashes across runs)', () => {
    const nullable = baseEvidence({ sha256: null, filename: null, mimeType: null, sizeBytes: null });
    const h1 = computeEvidenceHash(nullable);
    const h2 = computeEvidenceHash(nullable);
    expect(h1).toBe(h2);
    expect(h1).not.toBe(computeEvidenceHash(baseEvidence()));
  });

  it('the canonical string is a stable, inspectable JSON contract', () => {
    const canonical = canonicalizeEvidence(baseEvidence());
    expect(canonical).toBe(
      '{"id":"ev-1","organizationId":"org-1","caseId":"case-1","type":"LOG","sha256":"' +
        'a'.repeat(64) +
        '","filename":"notes.log","mimeType":"text/plain","sizeBytes":1024,"collectionTime":"2026-01-01T00:00:00.000Z"}'
    );
  });

  it('sha256Hex is a pure, deterministic SHA-256 of the exact input string', () => {
    expect(sha256Hex('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });
});
