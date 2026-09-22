import { createHash } from 'crypto';
import { Readable } from 'stream';
import { PrismaClient } from '@ciperscope/database';
import { RawEmailStore } from '@ciperscope/storage';
import { logger } from '@ciperscope/logger';
import { buildReportData, ReportInput } from './ReportDataBuilder';
import { renderReportPdf } from './PdfRenderer';

export function reportArtifactKey(reportId: string): string {
  return `reports/${reportId}.pdf`;
}

/**
 * Generates one forensic-report PDF for an already-QUEUED ForensicReport
 * row. Reads only already-persisted evidence (never re-runs analysis, never
 * fetches external intelligence) — this is a pure aggregation + render step.
 * Errors are caught and persisted onto the row as FAILED/errorMessage rather
 * than left to a bare job failure, so GET /reports/:id always reflects the
 * true terminal state even if the caller never inspects job history.
 */
export class ReportGenerationWorker {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly rawEmailStore: RawEmailStore
  ) {}

  async generate(reportId: string, organizationId: string): Promise<void> {
    const report = await this.prisma.forensicReport.findUnique({ where: { id: reportId } });
    if (!report || report.organizationId !== organizationId) {
      throw new Error(`ForensicReport ${reportId} not found for organization ${organizationId}`);
    }

    await this.prisma.forensicReport.update({
      where: { id: reportId },
      data: { status: 'GENERATING' },
    });

    try {
      const input = await this.collectReportInput(reportId, report.emailId, organizationId, report.reportVersion);
      const reportData = buildReportData(input);
      const pdfBuffer = await renderReportPdf(reportData);
      const sha256 = createHash('sha256').update(pdfBuffer).digest('hex');
      const artifactLocation = reportArtifactKey(reportId);

      await this.rawEmailStore.put(artifactLocation, Readable.from(pdfBuffer));

      await this.prisma.forensicReport.update({
        where: { id: reportId },
        data: {
          status: 'COMPLETED',
          artifactLocation,
          sha256,
          generatedAt: new Date(),
          errorMessage: null,
        },
      });

      logger.info({ reportId, emailId: report.emailId, sha256 }, 'Forensic report generated');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error generating report';
      logger.error({ reportId, err: error }, 'Forensic report generation failed');
      await this.prisma.forensicReport.update({
        where: { id: reportId },
        data: { status: 'FAILED', errorMessage: message },
      });
      throw error;
    }
  }

  private async collectReportInput(
    reportId: string,
    emailId: string,
    organizationId: string,
    reportVersion: string
  ): Promise<ReportInput> {
    const email = await this.prisma.email.findUnique({ where: { id: emailId } });
    if (!email || email.organizationId !== organizationId) {
      throw new Error(`Email ${emailId} not found for organization ${organizationId}`);
    }

    const [addresses, relayHops, spf, dkim, dmarc, urls, attachments, latestRiskAssessment, latestMlInference] =
      await Promise.all([
        this.prisma.emailAddress.findMany({ where: { emailId } }),
        this.prisma.relayHop.findMany({ where: { emailId }, orderBy: { hopOrder: 'asc' } }),
        this.prisma.spfVerification.findMany({ where: { emailId } }),
        this.prisma.dkimVerification.findMany({ where: { emailId } }),
        this.prisma.dmarcVerification.findUnique({ where: { emailId } }),
        this.prisma.emailUrl.findMany({ where: { emailId } }),
        this.prisma.emailAttachment.findMany({ where: { emailId } }),
        this.prisma.riskAssessment.findFirst({
          where: { emailId },
          orderBy: { createdAt: 'desc' },
          include: { factors: true },
        }),
        this.prisma.mLInference.findFirst({ where: { emailId }, orderBy: { createdAt: 'desc' } }),
      ]);

    // ThreatIntelObservation is keyed by Indicator (value/type), not
    // directly by email — gather the set of indicator values genuinely
    // observed on this email (relay IPs + extracted URLs/domains) and look
    // up only those, so we never report CTI for indicators unrelated to
    // this email.
    const relayIps = relayHops.map((h) => h.sourceIp).filter((ip): ip is string => !!ip);
    const urlDomains = urls.map((u) => u.domain).filter((d): d is string => !!d);
    const urlValues = urls.map((u) => u.url);
    const indicatorValues = Array.from(new Set([...relayIps, ...urlDomains, ...urlValues]));

    const observations = indicatorValues.length === 0
      ? []
      : await this.prisma.threatIntelObservation.findMany({
          where: { indicator: { value: { in: indicatorValues } } },
          include: { indicator: true },
          orderBy: { observationTime: 'desc' },
        });

    const relevantIps = relayIps.filter((ip, i, arr) => arr.indexOf(ip) === i);
    const geoLocations = relevantIps.length === 0
      ? []
      : await this.prisma.geoLocation.findMany({ where: { ipAddress: { in: relevantIps } } });

    return {
      reportId,
      organizationId,
      reportVersion,
      email: {
        id: email.id,
        messageId: email.messageId,
        subject: email.subject,
        senderAddress: email.senderAddress,
        replyTo: email.replyTo,
        returnPath: email.returnPath,
        date: email.date,
        createdAt: email.createdAt,
        analysisStatus: email.analysisStatus,
        classification: email.classification,
        riskScore: email.riskScore,
      },
      addresses: addresses.map((a) => ({ address: a.address ?? a.raw, type: a.headerName })),
      relayHops: relayHops.map((h) => ({
        sourceIp: h.sourceIp,
        hopOrder: h.hopOrder,
        receivedHeader: h.receivedHeader,
        timestamp: h.timestamp,
      })),
      spf: spf.map((s) => ({ result: s.result, domain: s.domain, evaluatedIp: s.evaluatedIp, explanation: s.explanation })),
      dkim: dkim.map((d) => ({ result: d.result, domain: d.domain, selector: d.selector, explanation: d.explanation })),
      dmarc: dmarc
        ? { result: dmarc.result, orgDomain: dmarc.orgDomain, policy: dmarc.policy, explanation: dmarc.explanation }
        : null,
      urls: urls.map((u) => ({
        url: u.url,
        normalizedUrl: u.normalizedUrl,
        domain: u.domain,
        source: u.source,
        isObfuscated: u.isObfuscated,
        indicators: u.indicators,
      })),
      attachments: attachments.map((a) => ({
        id: a.id,
        filename: a.filename,
        mimeType: a.mimeType,
        sizeBytes: a.sizeBytes,
        sha256: a.sha256,
        actualMimeType: a.actualMimeType,
        isMismatch: a.isMismatch,
        isArchive: a.isArchive,
        archiveMetadata: a.archiveMetadata,
        apkMetadata: a.apkMetadata,
        qrFindings: a.qrFindings,
        threatIndicators: a.threatIndicators,
      })),
      geoLocations: geoLocations.map((g) => ({
        ipAddress: g.ipAddress,
        country: g.country,
        city: g.city,
        asn: g.asn,
        isp: g.isp,
        provider: g.provider,
      })),
      indicatorObservations: observations.map((o) => ({
        value: o.indicator.value,
        type: o.indicator.type,
        verdict: o.verdict,
        confidence: o.confidence,
        provider: o.provider,
        observationTime: o.observationTime,
      })),
      riskAssessment: latestRiskAssessment
        ? {
            overallScore: latestRiskAssessment.overallScore,
            riskLevel: latestRiskAssessment.riskLevel,
            version: latestRiskAssessment.version,
            factors: latestRiskAssessment.factors.map((f) => ({
              category: f.category,
              description: f.description,
              scoreContribution: f.scoreContribution,
            })),
          }
        : null,
      mlInference: latestMlInference
        ? { status: latestMlInference.status, prediction: latestMlInference.prediction, modelScore: latestMlInference.modelScore }
        : null,
    };
  }
}
