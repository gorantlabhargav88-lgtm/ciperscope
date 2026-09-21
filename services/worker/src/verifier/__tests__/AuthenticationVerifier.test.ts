import { describe, it, expect, vi, beforeEach } from 'vitest';
import { Readable } from 'stream';
import crypto, { KeyObject } from 'crypto';
import dns from 'dns/promises';
import { AuthenticationVerifier } from '../AuthenticationVerifier';
import { canonicalizeHeaderRelaxed, canonicalizeBodyRelaxed } from '../dkim/canonicalize';
import { selectSignedHeaders } from '../dkim/headerSelection';
import { RawHeader } from '../dkim/rawMessage';
import type { RawEmailStore } from '@ciperscope/storage';

vi.mock('dns/promises');
vi.mock('@ciperscope/logger', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}));

function signMessage(privateKey: KeyObject, allHeaders: RawHeader[], body: Buffer, headerNames: string[]): string {
  const selected = selectSignedHeaders(headerNames, allHeaders);
  const chunks = selected.map(h => Buffer.from(canonicalizeHeaderRelaxed(h), 'latin1'));
  const target = allHeaders[allHeaders.length - 1];
  const canonicalSigHeader = canonicalizeHeaderRelaxed(target).replace(/\r\n$/, '');
  const signedData = Buffer.concat([...chunks, Buffer.from(canonicalSigHeader, 'latin1')]);
  return crypto.sign('RSA-SHA256', signedData, privateKey).toString('base64');
}

describe('AuthenticationVerifier — DKIM raw-message wiring (Phase 8)', () => {
  let prismaMock: Record<string, unknown>;
  let rawEmailStoreMock: { exists: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
  let rsaPrivateKey: KeyObject;
  let rsaPublicKeyDer: string;

  beforeEach(() => {
    vi.resetAllMocks();
    vi.mocked(dns.resolveTxt).mockResolvedValue([]);

    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    rsaPrivateKey = pair.privateKey;
    rsaPublicKeyDer = pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

    rawEmailStoreMock = {
      exists: vi.fn().mockResolvedValue(false),
      get: vi.fn()
    };

    prismaMock = {
      email: { findUnique: vi.fn(), update: vi.fn() },
      $transaction: vi.fn().mockImplementation(async (callback: (tx: unknown) => Promise<void>) => {
        await callback(prismaMock);
      }),
      emailAuthenticationAnalysis: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
      spfVerification: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
      dkimVerification: { deleteMany: vi.fn(), createMany: vi.fn().mockResolvedValue({}) },
      dmarcVerification: { deleteMany: vi.fn(), create: vi.fn().mockResolvedValue({}) },
      dnsObservation: { deleteMany: vi.fn(), createMany: vi.fn().mockResolvedValue({}) }
    };
  });

  it('records an honest PERMERROR (never a fabricated pass) when the message claims a DKIM signature but the raw bytes are unavailable', async () => {
    prismaMock.email = {
      findUnique: vi.fn().mockResolvedValue({
        id: 'email-1',
        returnPath: null,
        rawStorageKey: null, // no raw storage key at all
        headers: [{ name: 'DKIM-Signature', value: 'v=1; a=rsa-sha256; d=example.com; s=s1; h=from; bh=x; b=y' }],
        addresses: [],
        relayHops: []
      })
    };

    const verifier = new AuthenticationVerifier(prismaMock as never, rawEmailStoreMock as unknown as RawEmailStore);
    await verifier.verifyEmail('email-1');

    expect(prismaMock.dkimVerification).toBeDefined();
    const createManyCall = (prismaMock.dkimVerification as { createMany: ReturnType<typeof vi.fn> }).createMany.mock.calls[0][0];
    expect(createManyCall.data).toHaveLength(1);
    expect(createManyCall.data[0].result).toBe('PERMERROR');
    expect(createManyCall.data[0].explanation).toMatch(/raw message unavailable/i);

    const analysisCreateCall = (prismaMock.emailAuthenticationAnalysis as { create: ReturnType<typeof vi.fn> }).create.mock.calls[0][0];
    expect(analysisCreateCall.data.dkim).toBe('PERMERROR');
  });

  it('performs real cryptographic verification end-to-end and persists an honest PASS when the raw message and DNS key are both genuinely valid', async () => {
    const from: RawHeader = { name: 'From', value: ' test@example.com', raw: 'From: test@example.com' };
    const body = Buffer.from('Hello world.\r\n', 'latin1');
    const bh = crypto.createHash('sha256').update(canonicalizeBodyRelaxed(body)).digest('base64');
    const rawSigTemplate = `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; h=from; bh=${bh}; b=`;
    const templateHeader: RawHeader = { name: 'DKIM-Signature', value: rawSigTemplate.slice('DKIM-Signature:'.length), raw: rawSigTemplate };
    const signature = signMessage(rsaPrivateKey, [from, templateHeader], body, ['from']);
    const finalRaw = rawSigTemplate.replace(/b=$/, `b=${signature}`);
    const rawMessageBuffer = Buffer.from(
      `From: test@example.com\r\n${finalRaw}\r\n\r\n${body.toString('latin1')}`,
      'latin1'
    );

    prismaMock.email = {
      findUnique: vi.fn().mockResolvedValue({
        id: 'email-1',
        returnPath: null,
        rawStorageKey: 'key-1',
        headers: [{ name: 'DKIM-Signature', value: finalRaw.slice('DKIM-Signature:'.length) }],
        addresses: [],
        relayHops: []
      })
    };
    rawEmailStoreMock.exists.mockResolvedValue(true);
    rawEmailStoreMock.get.mockResolvedValue(Readable.from([rawMessageBuffer]));
    vi.mocked(dns.resolveTxt).mockImplementation(async (domain: string) => {
      if (domain === 'sel1._domainkey.example.com') return [[`v=DKIM1; k=rsa; p=${rsaPublicKeyDer}`]];
      return [];
    });

    const verifier = new AuthenticationVerifier(prismaMock as never, rawEmailStoreMock as unknown as RawEmailStore);
    await verifier.verifyEmail('email-1');

    const createManyCall = (prismaMock.dkimVerification as { createMany: ReturnType<typeof vi.fn> }).createMany.mock.calls[0][0];
    expect(createManyCall.data[0].result).toBe('PASS');
    expect(createManyCall.data[0].bodyHashResult).toBe('PASS');

    const analysisCreateCall = (prismaMock.emailAuthenticationAnalysis as { create: ReturnType<typeof vi.fn> }).create.mock.calls[0][0];
    expect(analysisCreateCall.data.dkim).toBe('PASS');
  });

  it('does not query DKIM at all (result stays NONE) when the message has no DKIM-Signature header — SPF/DMARC-only emails are unaffected', async () => {
    prismaMock.email = {
      findUnique: vi.fn().mockResolvedValue({
        id: 'email-1',
        returnPath: null,
        rawStorageKey: null,
        headers: [],
        addresses: [],
        relayHops: []
      })
    };

    const verifier = new AuthenticationVerifier(prismaMock as never, rawEmailStoreMock as unknown as RawEmailStore);
    await verifier.verifyEmail('email-1');

    expect((prismaMock.dkimVerification as { createMany: ReturnType<typeof vi.fn> }).createMany).not.toHaveBeenCalled();
    const analysisCreateCall = (prismaMock.emailAuthenticationAnalysis as { create: ReturnType<typeof vi.fn> }).create.mock.calls[0][0];
    expect(analysisCreateCall.data.dkim).toBe('NONE');
    expect(rawEmailStoreMock.get).not.toHaveBeenCalled();
  });
});
