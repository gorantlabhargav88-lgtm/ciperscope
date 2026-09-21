import { describe, it, expect, beforeAll } from 'vitest';
import crypto, { KeyObject } from 'crypto';
import { verifyDkimCryptography, DkimCryptoInput } from '../verifyCryptography';
import { canonicalizeHeaderRelaxed, canonicalizeHeaderSimple, canonicalizeBodyRelaxed } from '../canonicalize';
import { selectSignedHeaders } from '../headerSelection';
import { RawHeader } from '../rawMessage';

/**
 * Builds a valid DKIM signature for a test message using the SAME
 * canonicalization/header-selection code the verifier uses, so this suite's
 * primary oracle is internal consistency (sign == verify's inverse), plus a
 * throwaway key generated fresh in-memory for the test run (never a real,
 * persisted, or reused key — "clearly non-secret" per the test-fixture
 * requirement).
 */
function signForTest(
  privateKey: crypto.KeyObject,
  algorithm: 'rsa-sha256' | 'ed25519-sha256',
  allHeaders: RawHeader[],
  targetHeaderIndex: number,
  body: Buffer,
  headerNames: string[],
  headerAlgo: 'simple' | 'relaxed',
  bodyAlgo: 'simple' | 'relaxed'
): { bh: string; b: string } {
  const canonBody = bodyAlgo === 'relaxed' ? canonicalizeBodyRelaxed : (b: Buffer) => Buffer.from(b.toString('latin1').replace(/(\r\n)+$/, '') + '\r\n', 'latin1');
  const bh = crypto.createHash('sha256').update(canonBody(body)).digest('base64');

  const canonHeader = headerAlgo === 'relaxed' ? canonicalizeHeaderRelaxed : canonicalizeHeaderSimple;
  const selected = selectSignedHeaders(headerNames, allHeaders);
  const chunks = selected.map(h => Buffer.from(canonHeader(h), 'latin1'));
  const target = allHeaders[targetHeaderIndex];
  const canonicalSigHeader = canonHeader(target).replace(/\r\n$/, '');
  const signedData = Buffer.concat([...chunks, Buffer.from(canonicalSigHeader, 'latin1')]);

  const signature =
    algorithm === 'ed25519-sha256'
      ? crypto.sign(null, signedData, privateKey)
      : crypto.sign('RSA-SHA256', signedData, privateKey);

  return { bh, b: signature.toString('base64') };
}

describe('verifyDkimCryptography', () => {
  let rsaPublicKey: KeyObject;
  let rsaPrivateKey: KeyObject;
  let ed25519PublicKey: KeyObject;
  let ed25519PrivateKey: KeyObject;

  const from: RawHeader = { name: 'From', value: ' test@example.com', raw: 'From: test@example.com' };
  const to: RawHeader = { name: 'To', value: ' recipient@example.org', raw: 'To: recipient@example.org' };
  const subject: RawHeader = { name: 'Subject', value: ' Hello', raw: 'Subject: Hello' };
  const body = Buffer.from('This is the test body.\r\n', 'latin1');

  function buildSignatureHeader(bh: string, algorithm: string): RawHeader {
    const raw = `DKIM-Signature: v=1; a=${algorithm}; c=relaxed/relaxed; d=example.com; s=test; h=from:to:subject; bh=${bh}; b=`;
    return { name: 'DKIM-Signature', value: raw.slice('DKIM-Signature:'.length), raw };
  }

  beforeAll(() => {
    // Fresh, throwaway keys generated only for this test run — never persisted, never real.
    const rsaPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    rsaPublicKey = rsaPair.publicKey;
    rsaPrivateKey = rsaPair.privateKey;

    const edPair = crypto.generateKeyPairSync('ed25519');
    ed25519PublicKey = edPair.publicKey;
    ed25519PrivateKey = edPair.privateKey;
  });

  function makeSignedInput(
    algorithm: 'rsa-sha256' | 'ed25519-sha256',
    privateKey: KeyObject,
    publicKey: KeyObject,
    overrides?: Partial<{ headers: RawHeader[]; body: Buffer }>
  ): DkimCryptoInput {
    const headers = overrides?.headers ?? [from, to, subject];
    const testBody = overrides?.body ?? body;
    const headerNames = ['from', 'to', 'subject'];

    // Compute bh against the real body first, to build a syntactically complete signature header.
    const bhOnly = crypto.createHash('sha256').update(canonicalizeBodyRelaxed(testBody)).digest('base64');
    const sigHeader = buildSignatureHeader(bhOnly, algorithm);
    const allHeaders = [...headers, sigHeader];

    const { bh, b } = signForTest(privateKey, algorithm, allHeaders, allHeaders.length - 1, testBody, headerNames, 'relaxed', 'relaxed');

    return {
      targetHeader: sigHeader,
      allHeaders,
      body: testBody,
      headerNames,
      headerAlgo: 'relaxed',
      bodyAlgo: 'relaxed',
      expectedBodyHash: bh,
      signatureBase64: b,
      algorithm,
      publicKey
    };
  }

  it('PASSES for a validly signed RSA-SHA256 message', () => {
    const input = makeSignedInput('rsa-sha256', rsaPrivateKey, rsaPublicKey);
    expect(verifyDkimCryptography(input)).toEqual({ status: 'PASS' });
  });

  it('PASSES for a validly signed Ed25519-SHA256 message', () => {
    const input = makeSignedInput('ed25519-sha256', ed25519PrivateKey, ed25519PublicKey);
    expect(verifyDkimCryptography(input)).toEqual({ status: 'PASS' });
  });

  it('FAILS with BODY_HASH_MISMATCH when the body is modified after signing', () => {
    const input = makeSignedInput('rsa-sha256', rsaPrivateKey, rsaPublicKey);
    input.body = Buffer.from('This is a TAMPERED body.\r\n', 'latin1');
    expect(verifyDkimCryptography(input)).toEqual({ status: 'BODY_HASH_MISMATCH' });
  });

  it('FAILS with SIGNATURE_INVALID when a signed header is modified after signing', () => {
    const input = makeSignedInput('rsa-sha256', rsaPrivateKey, rsaPublicKey);
    const tamperedFrom: RawHeader = { name: 'From', value: ' attacker@evil.example', raw: 'From: attacker@evil.example' };
    input.allHeaders = [tamperedFrom, to, subject, input.targetHeader];
    expect(verifyDkimCryptography(input)).toEqual({ status: 'SIGNATURE_INVALID' });
  });

  it('FAILS with SIGNATURE_INVALID for a syntactically valid but wrong signature (regression: length/presence is not proof)', () => {
    const input = makeSignedInput('rsa-sha256', rsaPrivateKey, rsaPublicKey);
    // A signature of the right shape/length but cryptographically wrong content —
    // proves the old "signature.length > 32" shortcut could never be relied upon.
    const fakeSignature = crypto.randomBytes(256).toString('base64');
    expect(fakeSignature.length).toBeGreaterThan(32);
    input.signatureBase64 = fakeSignature;
    expect(verifyDkimCryptography(input)).toEqual({ status: 'SIGNATURE_INVALID' });
  });

  it('rejects a cross-algorithm substitution (Ed25519 signature presented as RSA, or vice versa)', () => {
    const edInput = makeSignedInput('ed25519-sha256', ed25519PrivateKey, ed25519PublicKey);
    const rsaInput = makeSignedInput('rsa-sha256', rsaPrivateKey, rsaPublicKey);
    // Swap in the Ed25519 signature bytes but claim rsa-sha256 with the RSA key.
    rsaInput.signatureBase64 = edInput.signatureBase64;
    const result = verifyDkimCryptography(rsaInput);
    expect(result.status).not.toBe('PASS');
  });

  it('treats a malformed (non-base64-decodable-to-signature) b= as a safe MALFORMED failure, not a crash', () => {
    const input = makeSignedInput('rsa-sha256', rsaPrivateKey, rsaPublicKey);
    input.signatureBase64 = '';
    expect(verifyDkimCryptography(input)).toEqual({ status: 'MALFORMED', reason: 'Empty signature (b= tag)' });
  });
});
