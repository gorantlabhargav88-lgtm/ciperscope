import { describe, it, expect, vi, beforeAll } from 'vitest';
import crypto, { KeyObject } from 'crypto';
import { DkimVerifier } from '../DkimVerifier';
import { DnsResolver } from '../DnsResolver';
import { canonicalizeHeaderRelaxed, canonicalizeBodyRelaxed } from '../dkim/canonicalize';
import { selectSignedHeaders } from '../dkim/headerSelection';
import { RawHeader } from '../dkim/rawMessage';

function makeResolver(txtRecords: Record<string, string[]>): DnsResolver {
  const resolver = new DnsResolver(50, 5000);
  vi.spyOn(resolver, 'resolveTxt').mockImplementation(async (domain: string) => txtRecords[domain] ?? []);
  return resolver;
}

function signHeaders(privateKey: KeyObject, algorithm: 'rsa-sha256' | 'ed25519-sha256', allHeaders: RawHeader[], body: Buffer, headerNames: string[]): string {
  const canonBody = canonicalizeBodyRelaxed(body);
  void canonBody;
  const selected = selectSignedHeaders(headerNames, allHeaders);
  const chunks = selected.map(h => Buffer.from(canonicalizeHeaderRelaxed(h), 'latin1'));
  const target = allHeaders[allHeaders.length - 1];
  const canonicalSigHeader = canonicalizeHeaderRelaxed(target).replace(/\r\n$/, '');
  const signedData = Buffer.concat([...chunks, Buffer.from(canonicalSigHeader, 'latin1')]);
  const signature = algorithm === 'ed25519-sha256' ? crypto.sign(null, signedData, privateKey) : crypto.sign('RSA-SHA256', signedData, privateKey);
  return signature.toString('base64');
}

describe('DkimVerifier', () => {
  let rsaPublicKeyDer: string;
  let rsaPrivateKey: KeyObject;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    rsaPrivateKey = pair.privateKey;
    rsaPublicKeyDer = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  });

  const from: RawHeader = { name: 'From', value: ' test@example.com', raw: 'From: test@example.com' };
  const body = Buffer.from('Hello world.\r\n', 'latin1');
  const bh = crypto.createHash('sha256').update(canonicalizeBodyRelaxed(body)).digest('base64');

  function buildSignedMessage(overrides: { tags?: string } = {}) {
    const tagStr = overrides.tags ?? `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=from; bh=${bh}; b=`;
    const raw = `DKIM-Signature: ${tagStr}`;
    const sigHeader: RawHeader = { name: 'DKIM-Signature', value: raw.slice('DKIM-Signature:'.length), raw };
    const allHeaders = [from, sigHeader];
    const signature = signHeaders(rsaPrivateKey, 'rsa-sha256', allHeaders, body, ['from']);
    const finalRaw = raw.replace(/b=$/, `b=${signature}`);
    const finalSigHeader: RawHeader = { name: 'DKIM-Signature', value: finalRaw.slice('DKIM-Signature:'.length), raw: finalRaw };
    return { targetHeader: finalSigHeader, allHeaders: [from, finalSigHeader] };
  }

  it('PASSES a genuinely valid signature against the DNS-published key', async () => {
    const { targetHeader, allHeaders } = buildSignedMessage();
    const resolver = makeResolver({ 'sel1._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`] });
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(targetHeader, allHeaders, body);
    expect(result.result).toBe('PASS');
    expect(result.bodyHashResult).toBe('PASS');
  });

  it('returns PERMERROR (never PASS) when no DNS key record exists', async () => {
    const { targetHeader, allHeaders } = buildSignedMessage();
    const resolver = makeResolver({}); // no records anywhere
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(targetHeader, allHeaders, body);
    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toMatch(/no public key found/i);
  });

  it('returns PERMERROR (never PASS) for a revoked key (empty p=)', async () => {
    const { targetHeader, allHeaders } = buildSignedMessage();
    const resolver = makeResolver({ 'sel1._domainkey.example.com': ['v=DKIM1; k=rsa; p='] });
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(targetHeader, allHeaders, body);
    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toMatch(/revoked/i);
  });

  it('returns PERMERROR and never attempts crypto for an unsupported algorithm (rsa-sha1)', async () => {
    const { allHeaders } = buildSignedMessage({ tags: `v=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; s=sel1; h=from; bh=${bh}; b=deadbeef` });
    const target = allHeaders[1];
    const resolver = makeResolver({ 'sel1._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`] });
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(target, allHeaders, body);
    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toMatch(/unsupported dkim algorithm/i);
  });

  it('rejects a signature that uses the l= body-length tag, regardless of validity, to prevent truncation replay', async () => {
    const { allHeaders } = buildSignedMessage({ tags: `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=from; l=5; bh=${bh}; b=deadbeef` });
    const target = allHeaders[1];
    const resolver = makeResolver({ 'sel1._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`] });
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(target, allHeaders, body);
    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toMatch(/l=/);
  });

  it('returns PERMERROR for missing required tags without crashing', async () => {
    const malformed: RawHeader = { name: 'DKIM-Signature', value: ' v=1; a=rsa-sha256', raw: 'DKIM-Signature: v=1; a=rsa-sha256' };
    const resolver = makeResolver({});
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(malformed, [from, malformed], body);
    expect(result.result).toBe('PERMERROR');
  });

  it('returns TEMPERROR (not FAIL/PASS) on a DNS timeout', async () => {
    const { targetHeader, allHeaders } = buildSignedMessage();
    const resolver = new DnsResolver(50, 5000);
    vi.spyOn(resolver, 'resolveTxt').mockRejectedValue(new Error('DNS_TIMEOUT'));
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(targetHeader, allHeaders, body);
    expect(result.result).toBe('TEMPERROR');
  });

  it('FAILS (not PASS) when the algorithm claims rsa-sha256 but the DNS key type is ed25519', async () => {
    const { targetHeader, allHeaders } = buildSignedMessage();
    const resolver = makeResolver({ 'sel1._domainkey.example.com': ['v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='] });
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(targetHeader, allHeaders, body);
    expect(result.result).toBe('PERMERROR');
    expect(result.explanation).toMatch(/does not match dns key type/i);
  });

  it('regression: a syntactically well-formed but cryptographically wrong signature never passes (the old length-shortcut cannot resurface)', async () => {
    const forged = signHeaders(rsaPrivateKey, 'rsa-sha256', [from, { name: 'DKIM-Signature', value: '', raw: 'DKIM-Signature:' }], body, ['from']);
    // Build a signature-shaped tag list with a syntactically valid, length>32 base64 blob that is NOT the real signature.
    const bogusSig = Buffer.from(forged, 'base64').length > 32 ? forged : crypto.randomBytes(64).toString('base64');
    const tagStr = `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=from; bh=${bh}; b=${bogusSig}xx`;
    const raw = `DKIM-Signature: ${tagStr}`;
    const sigHeader: RawHeader = { name: 'DKIM-Signature', value: raw.slice('DKIM-Signature:'.length), raw };
    const allHeaders = [from, sigHeader];
    const resolver = makeResolver({ 'sel1._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`] });
    const verifier = new DkimVerifier(resolver);

    const result = await verifier.verify(sigHeader, allHeaders, body);
    expect(result.result).not.toBe('PASS');
  });

  describe('multiple TXT records at the selector name (DKIM10)', () => {
    it('DKIM10-1: resolves the valid key correctly when an unrelated TXT record coexists', async () => {
      const { targetHeader, allHeaders } = buildSignedMessage();
      const resolver = makeResolver({
        'sel1._domainkey.example.com': [
          'google-site-verification=unrelated-ownership-token',
          `v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`
        ]
      });
      const verifier = new DkimVerifier(resolver);

      const result = await verifier.verify(targetHeader, allHeaders, body);
      expect(result.result).toBe('PASS');
      expect(result.bodyHashResult).toBe('PASS');
    });

    it('DKIM10-2: multiple malformed/non-key TXT records classify deterministically as "no public key found", never PASS', async () => {
      const { targetHeader, allHeaders } = buildSignedMessage();
      const resolver = makeResolver({
        'sel1._domainkey.example.com': [
          'google-site-verification=unrelated-ownership-token',
          'v=spf1 -all',
          'some-other-unrelated=value'
        ]
      });
      const verifier = new DkimVerifier(resolver);

      const result = await verifier.verify(targetHeader, allHeaders, body);
      expect(result.result).toBe('PERMERROR');
      expect(result.explanation).toMatch(/no public key found/i);
    });

    it('DKIM10-3: multiple candidate DKIM-looking records are rejected deterministically, not resolved by array order', async () => {
      const { targetHeader, allHeaders } = buildSignedMessage();
      const otherPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const otherKeyDer = otherPair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

      const recordsInOneOrder = [`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`, `v=DKIM1; k=rsa; p=${otherKeyDer}`];
      const recordsInReverseOrder = [...recordsInOneOrder].reverse();

      for (const records of [recordsInOneOrder, recordsInReverseOrder]) {
        const resolver = makeResolver({ 'sel1._domainkey.example.com': records });
        const verifier = new DkimVerifier(resolver);
        const result = await verifier.verify(targetHeader, allHeaders, body);
        expect(result.result).toBe('PERMERROR');
        expect(result.explanation).toMatch(/multiple ambiguous dkim key records/i);
      }
    });

    it('DKIM10-4: a single valid TXT record still passes unchanged (no regression from the multi-record fix)', async () => {
      const { targetHeader, allHeaders } = buildSignedMessage();
      const resolver = makeResolver({ 'sel1._domainkey.example.com': [`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`] });
      const verifier = new DkimVerifier(resolver);

      const result = await verifier.verify(targetHeader, allHeaders, body);
      expect(result.result).toBe('PASS');
    });

    it('DKIM10-5: a revoked (empty p=) key record among multiple TXT records still fails as revoked, never PASS', async () => {
      const { targetHeader, allHeaders } = buildSignedMessage();
      const resolver = makeResolver({
        'sel1._domainkey.example.com': [
          'google-site-verification=unrelated-ownership-token',
          'v=DKIM1; k=rsa; p='
        ]
      });
      const verifier = new DkimVerifier(resolver);

      const result = await verifier.verify(targetHeader, allHeaders, body);
      expect(result.result).toBe('PERMERROR');
      expect(result.explanation).toMatch(/revoked/i);
    });
  });
});
