import PDFDocument from 'pdfkit';
import { ReportData } from './ReportDataBuilder';

// Bounds how much of any single free-text/URL/filename field is rendered,
// so attacker-controlled email content (an extremely long subject, URL, or
// filename) can never blow up the document size or overflow layout.
const MAX_FIELD_LENGTH = 500;
const MAX_LIST_ITEMS = 50;

function s(value: unknown): string {
  if (value === null || value === undefined) return 'N/A';
  const str = String(value);
  return str.length > MAX_FIELD_LENGTH ? `${str.slice(0, MAX_FIELD_LENGTH)}…` : str;
}

function limitList<T>(items: T[]): { shown: T[]; truncated: boolean } {
  if (items.length <= MAX_LIST_ITEMS) return { shown: items, truncated: false };
  return { shown: items.slice(0, MAX_LIST_ITEMS), truncated: true };
}

/**
 * Renders a deterministic forensic-report PDF from already-built report
 * data (see ReportDataBuilder.ts). pdfkit draws text/shapes directly — no
 * HTML is ever parsed or rendered, so there is no HTML/script-injection
 * surface for attacker-controlled email content (subject, URLs, filenames)
 * embedded in the report; every value is written as plain PDF text via `s()`.
 *
 * No browser dependency (pdfkit is pure JS, no native bindings, no
 * headless-browser process) and no filesystem writes — this returns an
 * in-memory Buffer; the caller decides where to persist it.
 */
export function renderReportPdf(data: ReportData): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, bufferPages: true, info: { Title: 'CipherScope Forensic Report' } });
    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const h1 = (text: string) => doc.moveDown(1).fontSize(16).font('Helvetica-Bold').text(text).moveDown(0.3);
    const h2 = (text: string) => doc.moveDown(0.8).fontSize(12).font('Helvetica-Bold').text(text).moveDown(0.2);
    const p = (text: string) => doc.fontSize(9).font('Helvetica').text(text);
    const kv = (label: string, value: string) => doc.fontSize(9).font('Helvetica').text(`${label}: `, { continued: true }).font('Helvetica-Bold').text(value);

    // Title
    doc.fontSize(20).font('Helvetica-Bold').text('CIPHERSCOPE FORENSIC REPORT', { align: 'center' });
    doc.fontSize(9).font('Helvetica').text(`Report ID: ${s(data.metadata.reportId)}  |  Version: ${s(data.metadata.reportVersion)}  |  Generated: ${s(data.metadata.generatedAt)}`, { align: 'center' });

    // 1. Executive Summary
    h1('1. Executive Summary');
    kv('Risk Level', s(data.executiveSummary.riskLevel));
    kv('Risk Score', s(data.executiveSummary.riskScore));
    kv('Classification', s(data.executiveSummary.classification));
    p(s(data.executiveSummary.explanation));

    // 2. Risk Assessment (factors)
    h1('2. Risk Assessment');
    if (data.riskFactors.length === 0) {
      p('No risk factors were persisted for this email.');
    } else {
      for (const f of data.riskFactors) {
        p(`• [${s(f.category)}] +${s(f.scoreContribution)} — ${s(f.description)}`);
      }
    }

    // 3. Case / Email Overview
    h1('3. Case / Email Overview');
    if (data.emailOverview.caseContext) {
      kv('Linked Case', s(data.emailOverview.caseContext.title));
      kv('Case Status', s(data.emailOverview.caseContext.status));
      kv('Case Priority', s(data.emailOverview.caseContext.priority));
    } else {
      p('This email is not linked to a case.');
    }
    kv('Subject', s(data.emailOverview.subject));
    kv('Sender', s(data.emailOverview.sender));
    kv('Recipients', data.emailOverview.recipients.length > 0 ? data.emailOverview.recipients.map(s).join(', ') : 'N/A');
    kv('Reply-To', s(data.emailOverview.replyTo));
    kv('Date', s(data.emailOverview.date));
    kv('Message-ID', s(data.emailOverview.messageId));
    kv('Ingested At', s(data.emailOverview.ingestedAt));
    if (data.emailOverview.relayHops.length > 0) {
      doc.moveDown(0.3);
      p('Relay Hops:');
      for (const hop of limitList(data.emailOverview.relayHops).shown) {
        p(`  Hop ${hop.hopOrder}: ${s(hop.sourceIp)}`);
      }
    }

    // 4. Authentication Analysis
    h1('4. Authentication Analysis');
    if (data.authentication.spf.length === 0) {
      p('SPF: not observed');
    } else {
      for (const spf of data.authentication.spf) p(`SPF: ${s(spf.result)} (domain: ${s(spf.domain)}, ip: ${s(spf.evaluatedIp)})`);
    }
    if (data.authentication.dkim.length === 0) {
      p('DKIM: not observed');
    } else {
      for (const dkim of data.authentication.dkim) p(`DKIM: ${s(dkim.result)} (domain: ${s(dkim.domain)}, selector: ${s(dkim.selector)})`);
    }
    if (data.authentication.dmarc === 'NOT_OBSERVED') {
      p('DMARC: not observed');
    } else {
      p(`DMARC: ${s(data.authentication.dmarc.result)} (org domain: ${s(data.authentication.dmarc.orgDomain)}, policy: ${s(data.authentication.dmarc.policy)})`);
    }

    // 5. URL & Domain Intelligence
    h1('5. URL & Domain Intelligence');
    if (data.urlIntelligence.length === 0) {
      p('No URLs were extracted from this email.');
    } else {
      const { shown, truncated } = limitList(data.urlIntelligence);
      for (const u of shown) {
        p(`• ${s(u.url)} [source: ${s(u.source)}]${u.indicators.length > 0 ? ` — indicators: ${u.indicators.map(s).join(', ')}` : ''}`);
      }
      if (truncated) p(`… and ${data.urlIntelligence.length - shown.length} more URL(s) not shown (see full data via the API).`);
    }

    // 6. IP & Geolocation Intelligence
    h1('6. IP & Geolocation Intelligence');
    if (data.ipDomainIntelligence.length === 0) {
      p('No relay IPs were observed for this email.');
    } else {
      for (const ip of data.ipDomainIntelligence) {
        const geo = ip.geolocation === 'UNAVAILABLE' ? 'geolocation unavailable' : `${s(ip.geolocation.city)}, ${s(ip.geolocation.country)} (ASN ${s(ip.geolocation.asn)}, ${s(ip.geolocation.provider)}) — approximate network geolocation, not a precise physical location`;
        const rep = ip.reputation === 'NOT_OBSERVED' ? 'no CTI observation' : `${s(ip.reputation.verdict)} (${s(ip.reputation.provider)})`;
        p(`• ${s(ip.ip)} [${s(ip.classification)}] — ${geo} — reputation: ${rep}`);
      }
    }

    // 7. Attachment Analysis + 8. APK Static Analysis (combined per attachment) + 9. QR Code Analysis
    h1('7. Attachment Analysis');
    if (data.attachments.length === 0) {
      p('No attachments were present on this email.');
    } else {
      for (const a of data.attachments) {
        h2(s(a.filename));
        kv('SHA-256', s(a.sha256));
        kv('Declared / Actual MIME', `${s(a.declaredMimeType)} / ${s(a.actualMimeType)}`);
        kv('Signature Mismatch', a.mismatch ? 'YES' : 'No');
        if (a.threatIndicators.length > 0) kv('Threat Indicators', a.threatIndicators.map(s).join(', '));

        if (a.apkMetadata) {
          const apk = a.apkMetadata as Record<string, unknown>;
          doc.fontSize(9).font('Helvetica-Oblique').text('  Android APK — Static Analysis:');
          kv('  Package', s(apk.packageName));
          kv('  Signed', apk.hasV1JarSigning || apk.hasV2SigningBlock ? 'Yes' : 'No');
          const perms = Array.isArray(apk.suspiciousPermissions) ? apk.suspiciousPermissions : [];
          if (perms.length > 0) kv('  Suspicious Permissions', perms.map(s).join(', '));
        }
        if (a.qrFindings) {
          const qr = a.qrFindings as { codes?: Array<{ payload: string; type: string }> };
          if (Array.isArray(qr.codes) && qr.codes.length > 0) {
            doc.fontSize(9).font('Helvetica-Oblique').text('  QR Code Analysis:');
            for (const code of limitList(qr.codes).shown) {
              p(`    [${s(code.type)}] ${s(code.payload)}`);
            }
          }
        }
      }
    }

    // 10. CTI Findings
    h1('10. CTI Findings');
    if (data.cti.length === 0) {
      p('No CTI observations were recorded for indicators from this email.');
    } else {
      for (const c of limitList(data.cti).shown) {
        p(`• ${s(c.indicator)} [${s(c.type)}] — ${s(c.verdict)} (provider: ${s(c.provider)}, observed: ${s(c.observedAt)})`);
      }
    }

    // 11. Evidence Graph Summary
    h1('11. Evidence Graph Summary');
    const eg = data.evidenceGraphSummary;
    p(`URLs: ${eg.urlCount}  |  Domains: ${eg.domainCount}  |  IPs: ${eg.ipCount}  |  Attachments: ${eg.attachmentCount}`);
    p(`APKs: ${eg.apkCount}  |  QR Codes: ${eg.qrCodeCount}  |  CTI Observations: ${eg.ctiObservationCount}  |  Geolocated IPs: ${eg.geolocatedIpCount}`);
    p('Full graph with node/edge provenance available via GET /emails/:emailId/evidence-graph.');

    // 12. Forensic Timeline
    h1('12. Forensic Timeline');
    if (data.timeline.length === 0) {
      p('No timeline events available.');
    } else {
      for (const ev of limitList(data.timeline).shown) {
        p(`• [${s(ev.timestamp)}] ${s(ev.event)} (${s(ev.source)}) — ${s(ev.description)}`);
      }
    }

    // 13. Chain of Custody
    h1('13. Chain of Custody');
    if (data.chainOfCustody.attachmentHashes.length === 0) {
      p('No attachment evidence to establish chain of custody for.');
    } else {
      for (const item of data.chainOfCustody.attachmentHashes) {
        p(`• ${s(item.filename)}: ${s(item.sha256)}`);
      }
    }

    // 14. Limitations
    h1('14. Limitations');
    if (data.limitations.length === 0) {
      p('No known limitations for this report.');
    } else {
      for (const lim of data.limitations) p(`• ${s(lim)}`);
    }

    // 15. Report Integrity
    h1('15. Report Integrity');
    p('The SHA-256 of this exact PDF artifact is computed and persisted after generation; see the report metadata via the API.');
    p(`Report version: ${s(data.metadata.reportVersion)}  |  Generated: ${s(data.metadata.generatedAt)}`);

    doc.end();
  });
}
