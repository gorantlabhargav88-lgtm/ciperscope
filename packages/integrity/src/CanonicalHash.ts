import { createHash } from 'crypto';

export interface CanonicalEvidenceInput {
  id: string;
  organizationId: string;
  caseId: string;
  type: string;
  // The evidence's own content-identity hash (already computed at upload
  // time, see Evidence.sha256) — reused here rather than re-hashing
  // arbitrary filesystem/storage content, per Phase M's explicit
  // requirement to represent binary evidence by its existing hash.
  sha256: string | null;
  filename: string | null;
  mimeType: string | null;
  sizeBytes: number | null;
  collectionTime: Date;
}

/**
 * Deterministic canonical representation of one Evidence row for integrity
 * hashing. This exact field list and order IS the documented contract —
 * changing it changes every future hash, so treat it as append-only
 * (new fields go at the end) rather than reordered.
 *
 * Included (identity + content + collection facts, all effectively
 * immutable once evidence is collected):
 *   id, organizationId, caseId, type, sha256, filename, mimeType,
 *   sizeBytes, collectionTime (ISO 8601, millisecond precision).
 *
 * Deliberately EXCLUDED (documented per Phase M Step 2):
 *   - storageKey: can change independently of evidence identity (e.g. a
 *     storage-backend migration) — including it would make the hash
 *     unstable for evidence whose *content* never changed.
 *   - status: mutable (ACTIVE -> DELETED via soft delete) — a hash that
 *     changed when evidence was deleted would defeat the point of proving
 *     the evidence existed unmodified at collection time.
 *   - collectedById / sourceSystem: provenance metadata about *how* the
 *     evidence arrived, not part of *what* the evidence is.
 *   - updatedAt / any other mutable timestamp.
 *   - No secrets, tokens, or credentials exist on Evidence at all, so
 *     none are ever at risk of being included.
 *
 * null/undefined handling: every optional field is normalized to a fixed
 * sentinel string (empty string for strings, 0 for numbers) so the same
 * logical "missing" value always canonicalizes identically.
 */
export function canonicalizeEvidence(evidence: CanonicalEvidenceInput): string {
  // A literal object with explicit key order — JSON.stringify preserves
  // the insertion order of string keys, so this order is exactly what's
  // hashed (never derived from Object.keys() on external input, which
  // Phase M requires to be deterministic regardless of how the caller
  // happened to construct its object).
  const canonical = {
    id: evidence.id,
    organizationId: evidence.organizationId,
    caseId: evidence.caseId,
    type: evidence.type,
    sha256: evidence.sha256 ?? '',
    filename: evidence.filename ?? '',
    mimeType: evidence.mimeType ?? '',
    sizeBytes: evidence.sizeBytes ?? 0,
    collectionTime: evidence.collectionTime.toISOString(),
  };
  return JSON.stringify(canonical);
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** The evidence integrity hash: SHA-256 of the canonical representation. */
export function computeEvidenceHash(evidence: CanonicalEvidenceInput): string {
  return sha256Hex(canonicalizeEvidence(evidence));
}
