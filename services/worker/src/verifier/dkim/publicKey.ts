import crypto, { KeyObject } from 'crypto';

export type DkimKeyType = 'rsa' | 'ed25519';

// Standard fixed ASN.1 SubjectPublicKeyInfo prefix for an Ed25519 key
// (SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING }), used because
// RFC 8463's p= tag for ed25519 is the raw 32-byte key, not SPKI-wrapped
// DER like RSA's p= tag is.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export class DkimPublicKeyError extends Error {}

/**
 * Parses a DKIM DNS key record's p= value into a usable public key.
 * Throws DkimPublicKeyError for anything that isn't a valid, non-revoked
 * key for the given key type — callers must treat that as a verification
 * failure (PERMERROR), never as an implicit pass.
 */
export function parseDkimPublicKey(keyType: DkimKeyType, base64Value: string): KeyObject {
  const cleaned = base64Value.replace(/\s+/g, '');
  if (cleaned.length === 0) {
    // RFC 6376 §3.6.1: an empty p= value means the key has been revoked.
    throw new DkimPublicKeyError('DKIM public key revoked (empty p= tag)');
  }

  let der: Buffer;
  try {
    der = Buffer.from(cleaned, 'base64');
  } catch {
    throw new DkimPublicKeyError('Malformed base64 in p= tag');
  }
  if (der.length === 0) {
    throw new DkimPublicKeyError('Malformed base64 in p= tag');
  }

  try {
    if (keyType === 'ed25519') {
      if (der.length !== 32) {
        throw new DkimPublicKeyError(`Invalid Ed25519 public key length: ${der.length}`);
      }
      const spki = Buffer.concat([ED25519_SPKI_PREFIX, der]);
      return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    }
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (err) {
    if (err instanceof DkimPublicKeyError) throw err;
    throw new DkimPublicKeyError(`Malformed public key: ${err instanceof Error ? err.message : 'unknown error'}`);
  }
}
