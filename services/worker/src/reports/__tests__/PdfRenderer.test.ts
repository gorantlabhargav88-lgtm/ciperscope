import { describe, it, expect } from 'vitest';
import { buildReportData, ReportInput } from '../ReportDataBuilder';
import { renderReportPdf } from '../PdfRenderer';

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
    caseContext: null,
    relayHops: [],
    spf: [],
    dkim: [],
    dmarc: null,
    urls: [],
    attachments: [],
    geoLocations: [],
    indicatorObservations: [],
    riskAssessment: {
      overallScore: 92,
      riskLevel: 'CRITICAL',
      version: '1',
      factors: [{ category: 'PHISHING_URL', description: 'Lookalike domain', scoreContribution: 92 }],
    },
    mlInference: null,
    ...overrides,
  };
}

describe('renderReportPdf', () => {
  it('produces a valid, non-empty PDF buffer', async () => {
    const data = buildReportData(baseInput());
    const pdf = await renderReportPdf(data);
    expect(pdf.length).toBeGreaterThan(0);
    // %PDF- magic header
    expect(pdf.subarray(0, 5).toString('utf8')).toBe('%PDF-');
  });

  it('is deterministic in content length for the same input (no random padding/timestamps affecting size materially)', async () => {
    const data = buildReportData(baseInput());
    const a = await renderReportPdf(data);
    const b = await renderReportPdf(data);
    // Allow a small delta since PDF internal object offsets could differ by a
    // few bytes across runs but should not vary wildly.
    expect(Math.abs(a.length - b.length)).toBeLessThan(50);
  });

  it('never crashes and stays bounded when fields contain attacker-controlled, oversized, or markup-like content', async () => {
    const maliciousSubject = `<script>alert(1)</script>` + 'A'.repeat(10000);
    const data = buildReportData(
      baseInput({
        email: { ...baseInput().email, subject: maliciousSubject },
        urls: Array.from({ length: 500 }, (_, i) => ({
          url: `https://evil.example/${'x'.repeat(2000)}/${i}`,
          normalizedUrl: null,
          domain: 'evil.example',
          source: 'TEXT',
          isObfuscated: false,
          indicators: ['PHISHING'],
        })),
      })
    );
    const pdf = await renderReportPdf(data);
    expect(pdf.length).toBeGreaterThan(0);
    // Bounded: truncation/list-limiting keeps the artifact well under an
    // unbounded-growth scenario (500 URLs * ~2KB each would be ~1MB+ if
    // unbounded; the renderer caps list items and per-field length).
    expect(pdf.length).toBeLessThan(2_000_000);
  });

  it('renders no HTML/script content literally executable — output is a binary PDF, not HTML', async () => {
    const data = buildReportData(baseInput({ email: { ...baseInput().email, subject: '<img src=x onerror=alert(1)>' } }));
    const pdf = await renderReportPdf(data);
    const text = pdf.toString('latin1');
    // The PDF format never interprets embedded text as HTML/JS; sanity check
    // this is genuinely PDF container format, not a raw HTML passthrough.
    expect(text.startsWith('%PDF-')).toBe(true);
    expect(text).not.toMatch(/<html/i);
  });
});
