import { PrismaClient, UrlExtractionSource } from '@ciperscope/database';
import { RawEmailStore } from '@ciperscope/storage';
import { UrlExtractor } from './UrlExtractor';
import { AttachmentAnalyzer } from './AttachmentAnalyzer';
import { analyzeQrCodes, QrAnalysisResult } from './QrCodeAnalyzer';
import {
  computeUniversalIndicators,
  computeApkIndicators,
  AttachmentThreatIndicator,
} from './AttachmentThreatIndicators';
import { logger } from '@ciperscope/logger';
import { simpleParser } from 'mailparser';
import { Readable } from 'stream';
import psl from 'psl';
import {
  completeEmailOutboxEvent,
  EmailProcessingStage,
  ensureEmailOutboxEvent,
} from '@ciperscope/queue';

type UrlCreateData = {
  emailId: string;
  url: string;
  normalizedUrl: string | null;
  source: UrlExtractionSource;
  isObfuscated: boolean;
  indicators: string[];
  domain: string | null;
};

interface EmailStageHandoff {
  outboxEventId?: string;
  organizationId: string;
  requestId?: string;
  traceId?: string;
}

/** Registrable domain for a URL (same `psl` library already used by
 *  BrandImpersonationDetector) — populates the previously-always-null
 *  EmailUrl.domain column, enabling per-domain intelligence lookups
 *  without needing to re-derive it from the URL string every time. */
function extractRegistrableDomain(url: string): string | null {
  try {
    const hostname = new URL(url).hostname;
    return psl.get(hostname.toLowerCase());
  } catch {
    return null;
  }
}

const DUPLICATE_HASH_INDICATOR: Omit<AttachmentThreatIndicator, 'description'> = {
  category: 'DUPLICATE_HASH_SEEN',
  severity: 'LOW',
  confidence: 'MEDIUM',
  source: 'ThreatAnalyzer',
  analyzerVersion: '1.0.0',
};

export class ThreatAnalyzer {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly rawEmailStore: RawEmailStore
  ) {}

  public async analyzeEmail(emailId: string, handoff?: EmailStageHandoff): Promise<void> {
    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        mimeParts: true,
        urls: true,
        attachments: true
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    logger.info({ emailId }, 'Starting Phase 10 Threat Analysis');

    const urlsToCreate: UrlCreateData[] = [];

    // We only process if we have a rawStorageKey to fetch attachments from,
    // unless MimeParts already contain inline text we can parse.
    // For now, let's assume we can fetch the full raw email to extract the text and attachments.
    // Wait, EmailForensicParser doesn't save the parsed text directly in DB, it only saves MimePart metadata.
    // So we need to re-parse or extract the specific parts.
    // To do it efficiently and safely, since mailparser streams, we can re-parse the raw stream to get text/html content
    // OR we could have saved it. Let's just re-parse the raw email using simpleParser to get the text and html bodies,
    // and process attachments.

    if (!email.rawStorageKey) {
       logger.warn({ emailId }, 'No rawStorageKey found for email, cannot perform threat analysis');
       throw new Error(`Raw email storage key missing for threat analysis: ${emailId}`);
    }

    const rawExists = await this.rawEmailStore.exists(email.rawStorageKey);
    if (!rawExists) {
       throw new Error(`Raw email missing for analysis: ${email.rawStorageKey}`);
    }

    const stream = await this.rawEmailStore.get(email.rawStorageKey);
    const parsed = await simpleParser(stream, {
      skipHtmlToText: true,
      skipImageLinks: true,
      skipTextToHtml: true,
      skipTextLinks: true,
    });

    // 1. Analyze URLs in Text Body
    if (parsed.text) {
      const extracted = UrlExtractor.extractFromText(parsed.text);
      extracted.forEach(u => {
        urlsToCreate.push({
          emailId,
          url: u.originalObservedUrl,
          normalizedUrl: u.normalizedUrl,
          source: UrlExtractionSource.TEXT,
          isObfuscated: u.isObfuscated,
          indicators: u.indicators,
          domain: extractRegistrableDomain(u.originalObservedUrl),
        });
      });
    }

    // 2. Analyze URLs in HTML Body
    if (parsed.html) {
      const extracted = UrlExtractor.extractFromHtml(parsed.html);
      extracted.forEach(u => {
        urlsToCreate.push({
          emailId,
          url: u.originalObservedUrl,
          normalizedUrl: u.normalizedUrl,
          source: UrlExtractionSource[u.source] || UrlExtractionSource.OTHER,
          isObfuscated: u.isObfuscated,
          indicators: u.indicators,
          domain: extractRegistrableDomain(u.originalObservedUrl),
        });
      });
    }

    // 3. Analyze Attachments
    const attachmentUpdates: { id: string; data: Record<string, unknown> }[] = [];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const newAttachments: any[] = [];

    if (parsed.attachments && parsed.attachments.length > 0) {
      for (const att of parsed.attachments) {
         // Create a readable stream from the attachment content (buffer)
         const attStream = Readable.from(att.content);

         const ext = att.filename ? att.filename.split('.').pop() : undefined;
         const declaredMime = att.contentType || 'application/octet-stream';

         try {
            const analysis = await AttachmentAnalyzer.analyze(attStream, declaredMime, ext);

            const indicators: AttachmentThreatIndicator[] = computeUniversalIndicators({
               filename: att.filename || 'unknown',
               declaredMimeType: declaredMime,
               actualMimeType: analysis.actualMimeType,
               isMismatch: analysis.isMismatch,
               isArchive: analysis.isArchive,
               archiveHasTraversal: analysis.archiveMetadata?.hasTraversal ?? false,
               archiveHasNestedArchive: analysis.archiveMetadata?.hasNestedArchive ?? false,
               archiveError: analysis.archiveMetadata?.error ?? null,
               entropy: analysis.entropy,
            });

            if (analysis.apkAnalysis) {
               indicators.push(...computeApkIndicators(analysis.apkAnalysis));
            }

            // QR analysis: image attachments only. Wrapped in its own
            // try/catch (on top of analyzeQrCodes' own internal safe
            // failure handling) so a QR-decode problem can never fail
            // this attachment's analysis, let alone the whole email.
            let qrResult: QrAnalysisResult | null = null;
            if (analysis.actualMimeType && analysis.actualMimeType.startsWith('image/')) {
               try {
                  qrResult = await analyzeQrCodes(att.content as Buffer);
               } catch (qrErr: unknown) {
                  logger.warn({ err: qrErr, filename: att.filename }, 'QR analysis failed for image attachment');
               }
            }

            if (qrResult && qrResult.detected) {
               for (const code of qrResult.codes) {
                  if (code.type !== 'URL') continue;
                  // Reuses the exact same single-URL analysis path (IP
                  // literal/obfuscation/brand-impersonation/homoglyph/
                  // typosquat detection, normalization) that text/HTML URLs
                  // already go through — never a second, duplicate analyzer.
                  const analyzed = UrlExtractor.analyzeSingleUrl(code.payload, 'QR_CODE');
                  urlsToCreate.push({
                     emailId,
                     url: analyzed.originalObservedUrl,
                     normalizedUrl: analyzed.normalizedUrl,
                     source: UrlExtractionSource.QR_CODE,
                     isObfuscated: analyzed.isObfuscated,
                     indicators: analyzed.indicators,
                     domain: extractRegistrableDomain(analyzed.originalObservedUrl),
                  });
               }
            }

            if (analysis.sha256) {
               // Tenant-scoped: only correlate against attachments belonging to
               // this same organization's emails, never across tenants.
               const priorSighting = await this.prisma.emailAttachment.findFirst({
                  where: {
                     sha256: analysis.sha256,
                     emailId: { not: emailId },
                     email: { organizationId: email.organizationId },
                  },
                  select: { id: true },
               });
               if (priorSighting) {
                  indicators.push({
                     ...DUPLICATE_HASH_INDICATOR,
                     description: `This exact file (SHA-256 ${analysis.sha256}) has been seen on another email in this organization before.`,
                  });
               }
            }

            const apkMetadataJson = analysis.apkAnalysis
               ? JSON.parse(JSON.stringify(analysis.apkAnalysis))
               : null;
            const qrFindingsJson = qrResult && qrResult.detected
               ? JSON.parse(JSON.stringify(qrResult))
               : null;
            const threatIndicatorsJson = indicators.length > 0
               ? JSON.parse(JSON.stringify(indicators))
               : null;

            // Try to match with existing MimePart or EmailAttachment from Phase 7/8
            const existingAtt = email.attachments.find(a => a.filename === att.filename && a.sizeBytes === att.size);

            if (existingAtt) {
               attachmentUpdates.push({
                  id: existingAtt.id,
                  data: {
                     actualMimeType: analysis.actualMimeType,
                     isMismatch: analysis.isMismatch,
                     magicBytes: analysis.magicBytes,
                     isArchive: analysis.isArchive,
                     archiveMetadata: analysis.archiveMetadata ? JSON.parse(JSON.stringify(analysis.archiveMetadata)) : null,
                     sha256: analysis.sha256,
                     apkMetadata: apkMetadataJson,
                     qrFindings: qrFindingsJson,
                     threatIndicators: threatIndicatorsJson,
                  }
               });
            } else {
               newAttachments.push({
                  emailId,
                  filename: att.filename || 'unknown',
                  mimeType: declaredMime,
                  sizeBytes: att.size,
                  sha256: analysis.sha256,
                  actualMimeType: analysis.actualMimeType,
                  isMismatch: analysis.isMismatch,
                  magicBytes: analysis.magicBytes,
                  isArchive: analysis.isArchive,
                  archiveMetadata: analysis.archiveMetadata ? JSON.parse(JSON.stringify(analysis.archiveMetadata)) : null,
                  apkMetadata: apkMetadataJson,
                  qrFindings: qrFindingsJson,
                  threatIndicators: threatIndicatorsJson,
               });
            }
         } catch (err: unknown) {
            logger.error({ err, filename: att.filename }, 'Failed to analyze attachment');
         }
      }
    }

    // Filter out duplicates based on originalObservedUrl within the same
    // email — done here, after text/HTML AND attachment/QR extraction have
    // all run, so a URL appearing in more than one source (e.g. the same
    // link in both the email body and a QR code) is persisted exactly once.
    // First-seen-wins by insertion order (text/HTML sources are pushed
    // before QR sources above, so a body/HTML sighting takes precedence).
    const uniqueUrlsMap = new Map<string, UrlCreateData>();
    for (const u of urlsToCreate) {
      if (!uniqueUrlsMap.has(u.url)) {
         uniqueUrlsMap.set(u.url, u);
      }
    }
    const uniqueUrls = Array.from(uniqueUrlsMap.values());

    // Persist all results transactionally
    await this.prisma.$transaction(async (tx) => {
       if (uniqueUrls.length > 0) {
          // Check for existing URLs to prevent unique constraint errors if any
          await tx.emailUrl.createMany({
             data: uniqueUrls
          });
       }

       if (newAttachments.length > 0) {
          await tx.emailAttachment.createMany({
             data: newAttachments
          });
       }

       for (const update of attachmentUpdates) {
          await tx.emailAttachment.update({
             where: { id: update.id },
             data: update.data
          });
       }

       if (handoff) {
          await completeEmailOutboxEvent(tx, handoff.outboxEventId);
          await ensureEmailOutboxEvent(tx, {
             organizationId: handoff.organizationId,
             emailId,
             stage: EmailProcessingStage.CTI_ENRICHMENT,
             queueName: 'email-cti-enrichment',
             jobName: 'cti-enrichment',
             payload: {
                organizationId: handoff.organizationId,
                resourceId: emailId,
                emailId,
                operation: 'cti-enrichment',
                ...(handoff.requestId ? { requestId: handoff.requestId } : {}),
                ...(handoff.traceId ? { traceId: handoff.traceId } : {}),
             },
          });
       }
    });

    logger.info({ emailId, urlCount: uniqueUrls.length, attachmentCount: attachmentUpdates.length + newAttachments.length }, 'Phase 10 Threat Analysis completed');
  }
}
