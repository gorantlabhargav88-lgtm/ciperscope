import crypto from 'crypto';

/**
 * Authenticated symmetric encryption for reversible secrets at rest —
 * currently used for Gmail OAuth access/refresh tokens
 * (services/api/src/modules/integration, services/worker/src/integration).
 *
 * This is deliberately separate from services/api/src/utils/crypto.ts
 * (argon2 password hashing, opaque one-way session tokens) — those are
 * one-way and cannot be reversed to recover the original value, which is
 * required here since the real token must be sent back to Google's API.
 *
 * Algorithm: AES-256-GCM (authenticated encryption — tamper-evident, not
 * just confidential). The 256-bit key is derived from the operator-supplied
 * GMAIL_TOKEN_ENCRYPTION_KEY environment secret via a single SHA-256 hash,
 * purely to fit an arbitrary-length high-entropy operator secret into the
 * exact 32-byte key AES-256 requires — this is NOT a password-based KDF
 * (no scrypt/PBKDF2/Argon2 needed, since the input is already a
 * high-entropy secret rather than a human-memorable password) and does not
 * introduce a new cryptographic primitive beyond the standard hash+cipher
 * already used elsewhere in this codebase.
 *
 * Stored/serialized format (single string, so no schema/column change is
 * needed — Integration.accessToken/refreshToken remain plain String
 * columns): `v1:<ivHex>:<authTagHex>:<ciphertextHex>`.
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // 96-bit nonce, the recommended size for GCM
const FORMAT_VERSION = 'v1';

export class TokenDecryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenDecryptionError';
  }
}

function deriveKey(secret: string): Buffer {
  return crypto.createHash('sha256').update(secret, 'utf8').digest();
}

export function encryptToken(plaintext: string, encryptionKeySecret: string): string {
  const key = deriveKey(encryptionKeySecret);
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [FORMAT_VERSION, iv.toString('hex'), authTag.toString('hex'), ciphertext.toString('hex')].join(':');
}

export function decryptToken(encoded: string, encryptionKeySecret: string): string {
  const parts = encoded.split(':');
  if (parts.length !== 4 || parts[0] !== FORMAT_VERSION) {
    throw new TokenDecryptionError('Malformed or unrecognized encrypted-token envelope');
  }
  const [, ivHex, authTagHex, ciphertextHex] = parts;

  let iv: Buffer, authTag: Buffer, ciphertext: Buffer;
  try {
    iv = Buffer.from(ivHex, 'hex');
    authTag = Buffer.from(authTagHex, 'hex');
    ciphertext = Buffer.from(ciphertextHex, 'hex');
  } catch {
    throw new TokenDecryptionError('Malformed hex encoding in encrypted-token envelope');
  }
  if (iv.length !== IV_LENGTH_BYTES || authTag.length !== 16) {
    throw new TokenDecryptionError('Malformed or unrecognized encrypted-token envelope');
  }

  const key = deriveKey(encryptionKeySecret);
  try {
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    // GCM authentication failure (tampered ciphertext/tag) or a wrong key
    // both surface as the same generic decipher error — never distinguish
    // them in the message to avoid leaking oracle information.
    throw new TokenDecryptionError('Token decryption failed: authentication tag mismatch or wrong key');
  }
}
