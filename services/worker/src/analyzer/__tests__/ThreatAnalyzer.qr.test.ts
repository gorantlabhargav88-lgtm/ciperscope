import { describe, it, expect, vi, beforeAll } from 'vitest';
import { Readable } from 'stream';
import QRCode from 'qrcode';
import { ThreatAnalyzer } from '../ThreatAnalyzer';
import { PrismaClient } from '@ciperscope/database';
import { LocalRawEmailStore } from '@ciperscope/storage';

vi.mock('@ciperscope/logger', () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() } }));

/**
 * Integration-level coverage (Phase G): a real raw email, real image/QR
 * attachments (built with the `qrcode` devDependency), decoded by the real
 * production QrCodeAnalyzer, and routed through the real, unmodified
 * UrlExtractor.analyzeSingleUrl — only Prisma and the raw-email store are
 * mocked. Proves the QR → UrlExtractor → EmailUrl(QR_CODE) → existing
 * dedup wiring end to end, not each piece in isolation.
 */
describe('ThreatAnalyzer — QR code integration (Phase G)', () => {
  let rawEmail: Buffer;
  const sharedUrl = 'https://shared-real-text-url.example.com/path';
  const brandImpersonationUrl = 'https://amaz0n-login.example.com/verify';

  beforeAll(async () => {
    const duplicateQr = await QRCode.toBuffer(sharedUrl, { type: 'png', width: 200, margin: 4 });
    const brandQr = await QRCode.toBuffer(brandImpersonationUrl, { type: 'png', width: 200, margin: 4 });
    const corruptImage = Buffer.from('not a real png despite the declared content-type');

    const boundary = 'PhaseGBoundary';
    const parts = [
      `From: sender@example.com`,
      `To: victim@example.com`,
      `Subject: QR code integration test`,
      `Content-Type: multipart/mixed; boundary="${boundary}"`,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset=UTF-8',
      '',
      `Please review this link: ${sharedUrl}`,
      '',
      `--${boundary}`,
      'Content-Type: image/png',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="duplicate.png"',
      '',
      duplicateQr.toString('base64'),
      '',
      `--${boundary}`,
      'Content-Type: image/png',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="brand-impersonation.png"',
      '',
      brandQr.toString('base64'),
      '',
      `--${boundary}`,
      'Content-Type: image/png',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="corrupt.png"',
      '',
      corruptImage.toString('base64'),
      '',
      `--${boundary}--`,
      '',
    ];
    rawEmail = Buffer.from(parts.join('\r\n'));
  });

  function makeMocks() {
    const createdUrls: Record<string, unknown>[] = [];
    const createdAttachments: Record<string, unknown>[] = [];

    const txMock = {
      emailUrl: { createMany: vi.fn((args: { data: Record<string, unknown>[] }) => { createdUrls.push(...args.data); return Promise.resolve(); }) },
      emailAttachment: {
        createMany: vi.fn((args: { data: Record<string, unknown>[] }) => { createdAttachments.push(...args.data); return Promise.resolve(); }),
        update: vi.fn().mockResolvedValue({}),
      },
    };

    const prismaMock = {
      email: {
        findUnique: vi.fn().mockResolvedValue({
          id: 'email-qr-1',
          organizationId: 'org-1',
          rawStorageKey: 'org-1/email-qr-1.eml',
          attachments: [],
        }),
      },
      emailAttachment: {
        findFirst: vi.fn().mockResolvedValue(null), // no prior duplicate-hash sighting
      },
      $transaction: vi.fn(async (cb: (tx: unknown) => Promise<void>) => cb(txMock)),
    } as unknown as PrismaClient;

    const storeMock = {
      exists: vi.fn().mockResolvedValue(true),
      get: vi.fn().mockResolvedValue(Readable.from([rawEmail])),
    } as unknown as LocalRawEmailStore;

    return { prismaMock, storeMock, createdUrls, createdAttachments };
  }

  it('9/10. a QR-decoded URL is routed through the existing UrlExtractor and persisted as an EmailUrl with source QR_CODE', async () => {
    const { prismaMock, storeMock, createdUrls } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await analyzer.analyzeEmail('email-qr-1');

    const brandUrlRow = createdUrls.find((u) => u.url === brandImpersonationUrl);
    expect(brandUrlRow).toBeDefined();
    expect(brandUrlRow.source).toBe('QR_CODE');
    // Same brand-impersonation detection a text/HTML URL would get —
    // proves this went through the real, unmodified UrlExtractor logic,
    // not a separate/duplicated QR-specific analyzer.
    expect(brandUrlRow.indicators).toContain('BRAND_IMPERSONATION_SUBDOMAIN');
  });

  it('11. a URL present in both the email text and a QR code is persisted exactly once, not duplicated', async () => {
    const { prismaMock, storeMock, createdUrls } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await analyzer.analyzeEmail('email-qr-1');

    const matches = createdUrls.filter((u) => u.url === sharedUrl);
    expect(matches).toHaveLength(1);
    // Text/HTML extraction runs before the attachment/QR loop, so the
    // text-body sighting wins and is the one persisted.
    expect(matches[0].source).toBe('TEXT');
  });

  it('14. a QR decode failure on one attachment does not fail the rest of the email analysis', async () => {
    const { prismaMock, storeMock, createdUrls, createdAttachments } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await expect(analyzer.analyzeEmail('email-qr-1')).resolves.not.toThrow();

    // The corrupt.png attachment still gets persisted (analysis continues
    // past the QR-decode failure for that one attachment)...
    expect(createdAttachments.some((a) => a.filename === 'corrupt.png')).toBe(true);
    // ...and the OTHER attachments' real QR findings are still captured.
    expect(createdUrls.some((u) => u.url === brandImpersonationUrl)).toBe(true);
  });

  it('qrFindings is persisted on the attachment record for an image containing a QR code', async () => {
    const { prismaMock, storeMock, createdAttachments } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await analyzer.analyzeEmail('email-qr-1');

    const brandAttachment = createdAttachments.find((a) => a.filename === 'brand-impersonation.png');
    expect(brandAttachment.qrFindings).toBeTruthy();
    expect(brandAttachment.qrFindings.detected).toBe(true);
    expect(brandAttachment.qrFindings.codes[0].payload).toBe(brandImpersonationUrl);
  });

  it('an attachment with no QR code (corrupt image) has qrFindings null, not a fabricated result', async () => {
    const { prismaMock, storeMock, createdAttachments } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await analyzer.analyzeEmail('email-qr-1');

    const corruptAttachment = createdAttachments.find((a) => a.filename === 'corrupt.png');
    expect(corruptAttachment.qrFindings).toBeNull();
  });

  it('Phase H: EmailUrl.domain is populated with the registrable domain for both text and QR-sourced URLs', async () => {
    const { prismaMock, storeMock, createdUrls } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await analyzer.analyzeEmail('email-qr-1');

    const textUrlRow = createdUrls.find((u) => u.url === sharedUrl);
    const qrUrlRow = createdUrls.find((u) => u.url === brandImpersonationUrl);

    // psl.get() returns the registrable domain, not the full hostname —
    // matches BrandImpersonationDetector's existing use of the same library.
    expect(textUrlRow.domain).toBe('example.com');
    expect(qrUrlRow.domain).toBe('example.com');
  });

  it('12. QR-bearing attachments still go through the existing tenant-scoped duplicate-hash correlation, unchanged', async () => {
    const { prismaMock, storeMock } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);

    await analyzer.analyzeEmail('email-qr-1');

    const findFirstMock = (prismaMock as unknown as { emailAttachment: { findFirst: ReturnType<typeof vi.fn> } }).emailAttachment.findFirst;
    expect(findFirstMock).toHaveBeenCalled();
    for (const call of findFirstMock.mock.calls) {
      expect((call[0] as { where: { email: { organizationId: string } } }).where.email.organizationId).toBe('org-1');
    }
  });

  it('13. no secret/token content ever appears in the persisted QR/URL data for this fixture', async () => {
    const { prismaMock, storeMock, createdUrls, createdAttachments } = makeMocks();
    const analyzer = new ThreatAnalyzer(prismaMock, storeMock);
    await analyzer.analyzeEmail('email-qr-1');

    const serialized = JSON.stringify({ createdUrls, createdAttachments }).toLowerCase();
    expect(serialized).not.toMatch(/accesstoken|refreshtoken|password|apikey|secret/);
  });
});
