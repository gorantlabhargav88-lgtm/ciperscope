import { describe, it, expect } from 'vitest';
import { buildReportData, ReportInput } from '../ReportDataBuilder';

function baseInput(overrides: Partial<ReportInput> = {}): ReportInput {
  return {
    reportId: 'report-1',
    organizationId: 'org-1',
    reportVersion: '1.0',
    email: {
      id: 'email-1',
      messageId: '<abc@example.com>',
      subject: 'Test subject',
      senderAddress: 'attacker@evil.example',
      replyTo: null,
      returnPath: null,
      date: new Date('2026-01-01T00:00:00Z'),
      createdAt: new Date('2026-01-01T00:05:00Z'),
      analysisStatus: 'COMPLETED',
      classification: 'PHISHING',
      riskScore: 80,
    },
    addresses: [{ address: 'victim@example.com', type: 'TO' }],
    relayHops: [],
    spf: [],
    dkim: [],
    dmarc: null,
    urls: [],
    attachments: [],
    geoLocations: [],
    indicatorObservations: [],
    riskAssessment: null,
    mlInference: null,
    ...overrides,
  };
}

describe('buildReportData', () => {
  it('produces all 13 required report sections', () => {
    const data = buildReportData(baseInput());
    expect(data).toHaveProperty('metadata');
    expect(data).toHaveProperty('executiveSummary');
    expect(data).toHaveProperty('emailOverview');
    expect(data).toHaveProperty('authentication');
    expect(data).toHaveProperty('urlIntelligence');
    expect(data).toHaveProperty('ipDomainIntelligence');
    expect(data).toHaveProperty('attachments');
    expect(data).toHaveProperty('cti');
    expect(data).toHaveProperty('evidenceGraphSummary');
    expect(data).toHaveProperty('timeline');
    expect(data).toHaveProperty('riskFactors');
    expect(data).toHaveProperty('chainOfCustody');
    expect(data).toHaveProperty('limitations');
  });

  it('never fabricates missing intelligence — records honest limitations instead', () => {
    const data = buildReportData(
      baseInput({
        email: { ...baseInput().email, analysisStatus: 'PROCESSING' },
        riskAssessment: null,
        dmarc: null,
        spf: [],
        dkim: [],
        mlInference: null,
      })
    );
    expect(data.limitations.some((l) => l.includes('Risk assessment unavailable'))).toBe(true);
    expect(data.limitations.some((l) => l.includes('DMARC'))).toBe(true);
    expect(data.limitations.some((l) => l.includes('SPF'))).toBe(true);
    expect(data.limitations.some((l) => l.includes('DKIM'))).toBe(true);
    expect(data.limitations.some((l) => l.includes('ML classification'))).toBe(true);
    expect(data.authentication.dmarc).toBe('NOT_OBSERVED');
  });

  it('reports geolocation as UNAVAILABLE (never a guessed value) when no GeoLocation row exists for a relay IP', () => {
    const data = buildReportData(
      baseInput({ relayHops: [{ sourceIp: '203.0.113.5', hopOrder: 0, receivedHeader: 'from x', timestamp: null }] })
    );
    expect(data.ipDomainIntelligence).toHaveLength(1);
    expect(data.ipDomainIntelligence[0].geolocation).toBe('UNAVAILABLE');
    expect(data.limitations.some((l) => l.includes('Geolocation unavailable for 203.0.113.5'))).toBe(true);
  });

  it('includes real geolocation and CTI reputation when persisted', () => {
    const data = buildReportData(
      baseInput({
        relayHops: [{ sourceIp: '203.0.113.5', hopOrder: 0, receivedHeader: 'from x', timestamp: null }],
        geoLocations: [{ ipAddress: '203.0.113.5', country: 'US', city: 'Ashburn', asn: 'AS14618', isp: 'Amazon', provider: 'MaxMind' }],
        indicatorObservations: [
          { value: '203.0.113.5', type: 'IP', verdict: 'MALICIOUS', confidence: 90, provider: 'AbuseIPDB', observationTime: new Date('2026-01-01T00:03:00Z') },
        ],
      })
    );
    const ip = data.ipDomainIntelligence[0];
    expect(ip.geolocation).not.toBe('UNAVAILABLE');
    if (ip.geolocation === 'UNAVAILABLE') throw new Error('unreachable');
    expect(ip.geolocation.country).toBe('US');
    expect(ip.reputation).not.toBe('NOT_OBSERVED');
    if (ip.reputation === 'NOT_OBSERVED') throw new Error('unreachable');
    expect(ip.reputation.verdict).toBe('MALICIOUS');
  });

  it('includes URL, APK, and QR findings when present on an attachment', () => {
    const data = buildReportData(
      baseInput({
        urls: [{ url: 'https://evil.example/login', normalizedUrl: null, domain: 'evil.example', source: 'QR_CODE', isObfuscated: false, indicators: ['BRAND_IMPERSONATION'] }],
        attachments: [
          {
            id: 'att-1',
            filename: 'invoice.apk',
            mimeType: 'application/vnd.android.package-archive',
            sizeBytes: 1024,
            sha256: 'a'.repeat(64),
            actualMimeType: 'application/vnd.android.package-archive',
            isMismatch: false,
            isArchive: true,
            archiveMetadata: null,
            apkMetadata: { packageName: 'com.evil.app', suspiciousPermissions: ['SEND_SMS'] },
            qrFindings: { detected: true, codes: [{ type: 'URL', payload: 'https://evil.example/login' }] },
            threatIndicators: [{ category: 'SUSPICIOUS_PERMISSIONS' }],
          },
        ],
      })
    );
    expect(data.urlIntelligence).toHaveLength(1);
    expect(data.urlIntelligence[0].indicators).toContain('BRAND_IMPERSONATION');
    expect(data.attachments[0].apkMetadata).toMatchObject({ packageName: 'com.evil.app' });
    expect(data.attachments[0].qrFindings).toMatchObject({ detected: true });
    expect(data.attachments[0].threatIndicators).toContain('SUSPICIOUS_PERMISSIONS');
    expect(data.evidenceGraphSummary.apkCount).toBe(1);
    expect(data.evidenceGraphSummary.qrCodeCount).toBe(1);
  });

  it('includes CTI observations for indicators beyond IPs (e.g. domains)', () => {
    const data = buildReportData(
      baseInput({
        indicatorObservations: [
          { value: 'evil.example', type: 'DOMAIN', verdict: 'MALICIOUS', confidence: 75, provider: 'VirusTotal', observationTime: new Date('2026-01-01T00:02:00Z') },
        ],
      })
    );
    expect(data.cti).toHaveLength(1);
    expect(data.cti[0].indicator).toBe('evil.example');
    expect(data.evidenceGraphSummary.ctiObservationCount).toBe(1);
  });

  it('orders the timeline chronologically by real timestamps, undated events last', () => {
    const data = buildReportData(
      baseInput({
        email: {
          ...baseInput().email,
          createdAt: new Date('2026-01-01T00:10:00Z'),
        },
        relayHops: [{ sourceIp: '203.0.113.5', hopOrder: 0, receivedHeader: 'from x', timestamp: new Date('2026-01-01T00:00:00Z') }],
        riskAssessment: { overallScore: 90, riskLevel: 'CRITICAL', version: '1', factors: [{ category: 'PHISHING_URL', description: 'test', scoreContribution: 90 }] },
      })
    );
    const timestamps = data.timeline.map((t) => t.timestamp);
    const dated = timestamps.filter((t): t is string => t !== null);
    expect(dated).toEqual([...dated].sort());
    // Undated (RISK_ASSESSED) event comes after all dated events.
    expect(data.timeline[data.timeline.length - 1].event).toBe('RISK_ASSESSED');
  });

  it('surfaces risk factors correctly and matches the executive summary risk score', () => {
    const data = buildReportData(
      baseInput({
        riskAssessment: {
          overallScore: 95,
          riskLevel: 'CRITICAL',
          version: '1',
          factors: [
            { category: 'PHISHING_URL', description: 'Lookalike domain detected', scoreContribution: 50 },
            { category: 'MALICIOUS_ATTACHMENT', description: 'Disguised APK', scoreContribution: 45 },
          ],
        },
      })
    );
    expect(data.riskFactors).toHaveLength(2);
    expect(data.executiveSummary.riskScore).toBe(95);
    expect(data.executiveSummary.riskLevel).toBe('CRITICAL');
    expect(data.executiveSummary.explanation).toContain('CRITICAL');
  });

  it('handles a clean, no-threat email honestly (no fabricated risk)', () => {
    const data = buildReportData(
      baseInput({
        riskAssessment: { overallScore: 0, riskLevel: 'LOW', version: '1', factors: [] },
      })
    );
    expect(data.riskFactors).toHaveLength(0);
    expect(data.executiveSummary.explanation).toContain('no corroborating risk factors');
  });

  it('produces chain-of-custody hashes matching the attachment SHA-256 values', () => {
    const data = buildReportData(
      baseInput({
        attachments: [
          { id: 'att-1', filename: 'doc.pdf', mimeType: 'application/pdf', sizeBytes: 10, sha256: 'b'.repeat(64), actualMimeType: 'application/pdf', isMismatch: false, isArchive: false, archiveMetadata: null, apkMetadata: null, qrFindings: null, threatIndicators: null },
        ],
      })
    );
    expect(data.chainOfCustody.attachmentHashes).toEqual([{ filename: 'doc.pdf', sha256: 'b'.repeat(64) }]);
  });

  it('is a pure function — never throws, never touches network/DB, deterministic for the same input except generatedAt', () => {
    const input = baseInput();
    const a = buildReportData(input);
    const b = buildReportData(input);
    expect({ ...a, metadata: { ...a.metadata, generatedAt: '' } }).toEqual({ ...b, metadata: { ...b.metadata, generatedAt: '' } });
  });
});
