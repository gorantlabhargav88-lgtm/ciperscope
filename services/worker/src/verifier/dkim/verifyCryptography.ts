import crypto, { KeyObject } from 'crypto';
import { RawHeader } from './rawMessage';
import { canonicalizeHeaderSimple, canonicalizeHeaderRelaxed, canonicalizeBodySimple, canonicalizeBodyRelaxed } from './canonicalize';
import { selectSignedHeaders } from './headerSelection';

export type CanonicalizationMode = 'simple' | 'relaxed';
export type DkimAlgorithm = 'rsa-sha256' | 'ed25519-sha256';

export interface DkimCryptoInput {
  /** The specific DKIM-Signature header occurrence being verified. */
  targetHeader: RawHeader;
  /** Every header field in the message, in original order. */
  allHeaders: RawHeader[];
  body: Buffer;
  headerNames: string[];
  headerAlgo: CanonicalizationMode;
  bodyAlgo: CanonicalizationMode;
  /** The bh= tag value, with folding whitespace already stripped. */
  expectedBodyHash: string;
  /** The b= tag value, with folding whitespace already stripped. */
  signatureBase64: string;
  algorithm: DkimAlgorithm;
  publicKey: KeyObject;
}

export type DkimCryptoOutcome =
  | { status: 'PASS' }
  | { status: 'BODY_HASH_MISMATCH' }
  | { status: 'SIGNATURE_INVALID' }
  | { status: 'MALFORMED'; reason: string };

/**
 * Blanks the b= tag's value (RFC 6376 §3.7: "the value of the 'b=' tag
 * (including all surrounding whitespace) deleted (i.e., treated as the
 * empty string)"), leaving the tag name and every other tag untouched.
 */
function blankSignatureTagValue(text: string): string {
  return text.replace(/((?:^|;)\s*b\s*=\s*)([^;]*)/, '$1');
}

/**
 * Performs the actual RFC 6376 §3.7 cryptographic verification: body hash
 * comparison, then signed-header reconstruction and RSA/Ed25519 signature
 * verification via Node's built-in crypto. Pure and synchronous — DNS
 * lookups and tag parsing happen in the caller (DkimVerifier).
 */
export function verifyDkimCryptography(input: DkimCryptoInput): DkimCryptoOutcome {
  const canonHeader = input.headerAlgo === 'relaxed' ? canonicalizeHeaderRelaxed : canonicalizeHeaderSimple;
  const canonBody = input.bodyAlgo === 'relaxed' ? canonicalizeBodyRelaxed : canonicalizeBodySimple;

  const canonicalBody = canonBody(input.body);
  const actualBodyHash = crypto.createHash('sha256').update(canonicalBody).digest('base64');
  if (actualBodyHash !== input.expectedBodyHash) {
    return { status: 'BODY_HASH_MISMATCH' };
  }

  const selectedHeaders = selectSignedHeaders(input.headerNames, input.allHeaders);
  const headerChunks = selectedHeaders.map(h => Buffer.from(canonHeader(h), 'latin1'));

  const blankedTarget: RawHeader = {
    name: input.targetHeader.name,
    value: blankSignatureTagValue(input.targetHeader.value),
    raw: blankSignatureTagValue(input.targetHeader.raw)
  };
  // The DKIM-Signature header itself is included last, without a trailing CRLF.
  const canonicalSigHeader = canonHeader(blankedTarget).replace(/\r\n$/, '');

  const signedData = Buffer.concat([...headerChunks, Buffer.from(canonicalSigHeader, 'latin1')]);

  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(input.signatureBase64, 'base64');
  } catch {
    return { status: 'MALFORMED', reason: 'Malformed base64 in b= tag' };
  }
  if (signatureBytes.length === 0) {
    return { status: 'MALFORMED', reason: 'Empty signature (b= tag)' };
  }

  let verified: boolean;
  try {
    verified =
      input.algorithm === 'ed25519-sha256'
        ? crypto.verify(null, signedData, input.publicKey, signatureBytes)
        : crypto.verify('RSA-SHA256', signedData, input.publicKey, signatureBytes);
  } catch (err) {
    return { status: 'MALFORMED', reason: `Signature verification error: ${err instanceof Error ? err.message : 'unknown error'}` };
  }

  return verified ? { status: 'PASS' } : { status: 'SIGNATURE_INVALID' };
}
