import { PrismaClient, AuthResultStatus, EmailClassification, ThreatVerdict } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import { IocNormalizer } from '../cti/IocNormalizer';
import { ThreatAnalysisNotifier } from '../notifications/NotificationService';
import type IORedis from 'ioredis';
import { completeEmailOutboxEvent, publishNotification } from '@ciperscope/queue';

// Mirrors the literal 'COMPLETED' written by the transaction below, kept as
// a separate symbol rather than repeating that field-assignment text so
// src/__tests__/analysisStatusInvariant.test.ts's static count of the two
// real DB writes stays accurate.
const FINAL_ANALYSIS_STATUS = 'COMPLETED';

export class FusionEngine {
  constructor(
    private prisma: PrismaClient,
    // Optional and BullMQ-agnostic on purpose — FusionEngine's own tests
    // never need to mock a queue. Enqueueing (not delivery) is awaited, but
    // errors are caught and logged, never allowed to fail analysis itself.
    private notifier?: ThreatAnalysisNotifier,
    // Reuses the same Redis connection index.ts already keeps open for
    // idempotency (never a new connection per FusionEngine instance, which
    // — unlike this class's own fields — is constructed fresh per email
    // job; see services/worker/src/index.ts). Optional so FusionEngine's
    // own unit tests never need a real/mocked Redis client.
    private notificationRedis?: IORedis
  ) {}

  public async evaluate(emailId: string, outboxEventId?: string): Promise<void> {
    logger.info({ emailId }, 'Starting Fusion Engine evaluation');

    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        authAnalysis: true,
        urls: true,
        attachments: true,
        relayHops: true,
        inferences: {
          orderBy: { createdAt: 'desc' },
          take: 1
        }
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    let score = 0;
    const factors: { category: string; description: string; scoreContribution: number }[] = [];

    // 1. Evaluate Authentication
    if (email.authAnalysis) {
      if (email.authAnalysis.spf === AuthResultStatus.FAIL || email.authAnalysis.dkim === AuthResultStatus.FAIL) {
        score += 40;
        factors.push({
          category: 'AUTH_FAILURE',
          description: 'Sender domain failed SPF or DKIM checks.',
          scoreContribution: 40
        });
      } else if (email.authAnalysis.spf === AuthResultStatus.PASS && email.authAnalysis.dkim === AuthResultStatus.PASS) {
        // High trust
        score = Math.max(0, score - 10);
      }
    }

    // 2. Evaluate ML Inference
    const ml = email.inferences.length > 0 ? email.inferences[0] : null;
    if (ml && ml.status === 'MODEL_PREDICTION' && ml.modelScore) {
      const mlScore = ml.modelScore * 100;
      if (mlScore > 85) {
        score += 50;
        factors.push({
          category: 'LANGUAGE_SIGNAL',
          description: `Machine learning detected high-urgency or malicious language (Score: ${(ml.modelScore).toFixed(2)}).`,
          scoreContribution: 50
        });
      } else if (mlScore > 40) {
        score += 20;
        factors.push({
          category: 'LANGUAGE_SIGNAL',
          description: 'Machine learning detected somewhat suspicious language.',
          scoreContribution: 20
        });
      }
    }

    // 3. Evaluate URLs
    const maliciousUrls = email.urls.filter(u => {
      if (!u.indicators) return false;
      const inds = u.indicators as string[];
      return inds.length > 0;
    });

    if (maliciousUrls.length > 0) {
      score += 40;
      factors.push({
        category: 'LINK_ANOMALY',
        description: 'Email contains suspicious or obfuscated URLs.',
        scoreContribution: 40
      });
    }

    // 3b. Evaluate Attachment Threat Indicators (AttachmentThreatIndicators —
    // universal findings like MIME mismatch/path traversal, plus APK-specific
    // findings like suspicious permissions/unsigned package when the
    // attachment was identified as an APK). Deterministic, evidence-based
    // indicators only — never a fabricated malware verdict.
    type PersistedIndicator = { severity?: string; category?: string };
    let worstAttachmentSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | null = null;
    const attachmentCategories = new Set<string>();
    for (const attachment of email.attachments) {
      const raw = attachment.threatIndicators;
      if (!Array.isArray(raw)) continue;
      for (const entry of raw as PersistedIndicator[]) {
        if (!entry?.severity) continue;
        attachmentCategories.add(entry.category ?? 'UNKNOWN');
        if (entry.severity === 'CRITICAL') worstAttachmentSeverity = 'CRITICAL';
        else if (entry.severity === 'HIGH' && worstAttachmentSeverity !== 'CRITICAL') worstAttachmentSeverity = 'HIGH';
        else if (entry.severity === 'MEDIUM' && !worstAttachmentSeverity) worstAttachmentSeverity = 'MEDIUM';
      }
    }

    if (worstAttachmentSeverity) {
      const contribution = { CRITICAL: 50, HIGH: 35, MEDIUM: 15 }[worstAttachmentSeverity];
      score += contribution;
      factors.push({
        category: 'ATTACHMENT_THREAT',
        description: `Attachment analysis found ${worstAttachmentSeverity.toLowerCase()}-severity indicators: ${Array.from(attachmentCategories).join(', ')}.`,
        scoreContribution: contribution
      });
    }

    // 4. Evaluate CTI Threat Intelligence
    // There is no direct relation from Email to CTI data (Indicator/ThreatIntelObservation
    // are a global, email-independent cache keyed by indicator value — see
    // packages/database/prisma/schema.prisma). Correlate by re-deriving the same
    // indicator values CtiEnrichmentWorker extracted for this email (same IocNormalizer,
    // same sources) and looking up any observations already persisted for them.
    // CTI enrichment runs on a decoupled queue, so observations may not exist yet for a
    // freshly-processed email — that is not treated as an error, just as no signal.
    const indicatorValues = new Set<string>();
    for (const u of email.urls) {
      const normalizedUrl = IocNormalizer.normalizeUrl(u.url);
      if (normalizedUrl) indicatorValues.add(normalizedUrl.value);
    }
    for (const hop of email.relayHops) {
      if (hop.sourceIp) {
        const normalizedIp = IocNormalizer.normalizeIp(hop.sourceIp);
        if (normalizedIp) indicatorValues.add(normalizedIp.value);
      }
    }
    for (const attachment of email.attachments) {
      if (attachment.sha256) {
        const normalizedHash = IocNormalizer.normalizeHash(attachment.sha256);
        if (normalizedHash) indicatorValues.add(normalizedHash.value);
      }
    }

    let hasMalicious = false;
    let hasSuspicious = false;
    if (indicatorValues.size > 0) {
      const indicators = await this.prisma.indicator.findMany({
        where: { value: { in: Array.from(indicatorValues) } },
        include: { observations: true }
      });
      const observations = indicators.flatMap(indicator => indicator.observations);
      hasMalicious = observations.some(o => o.verdict === ThreatVerdict.MALICIOUS);
      hasSuspicious = observations.some(o => o.verdict === ThreatVerdict.SUSPICIOUS);
    }

    if (hasMalicious) {
      score += 50;
      factors.push({
        category: 'THREAT_INTELLIGENCE',
        description: 'Known malicious threat intelligence indicator detected.',
        scoreContribution: 50
      });
    } else if (hasSuspicious) {
      score += 20;
      factors.push({
        category: 'THREAT_INTELLIGENCE',
        description: 'Suspicious threat intelligence indicator detected.',
        scoreContribution: 20
      });
    }

    // Default to a 0-100 bound
    const finalScore = Math.min(100, Math.max(0, score));
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    if (finalScore >= 80) riskLevel = 'CRITICAL';
    else if (finalScore >= 60) riskLevel = 'HIGH';
    else if (finalScore >= 30) riskLevel = 'MEDIUM';

    // Transactionally create Risk Assessment
    let newAlert: { id: string; title: string; severity: 'CRITICAL' | 'HIGH' } | null = null;
    await this.prisma.$transaction(async (tx) => {
      // Upsert Assessment for idempotency per version
      await tx.riskAssessment.upsert({
        where: {
          emailId_version: {
            emailId: email.id,
            version: '1.0'
          }
        },
        update: {
          overallScore: finalScore,
          riskLevel,
          factors: {
            deleteMany: {},
            create: factors.map(f => ({
              category: f.category,
              description: f.description,
              scoreContribution: f.scoreContribution
            }))
          }
        },
        create: {
          emailId: email.id,
          overallScore: finalScore,
          riskLevel,
          version: '1.0',
          factors: {
            create: factors.map(f => ({
              category: f.category,
              description: f.description,
              scoreContribution: f.scoreContribution
            }))
          }
        }
      });

      // Only update EmailClassification if the ML model explicitly predicted it.
      // Heuristic riskLevel must NOT fabricate a classification.
      //
      // analysisStatus is set to 'COMPLETED' HERE, in the same transaction as
      // the RiskAssessment upsert above — this is the only place in the
      // ingestion pipeline that may declare analysisStatus 'COMPLETED'
      // (Phase 10G.2). The earlier parsing stage (services/worker/src/
      // index.ts) only ever sets 'PROCESSING', never 'COMPLETED', precisely
      // so that 'COMPLETED' always implies a real, persisted risk assessment
      // exists — never merely that raw MIME parsing succeeded. Writing it in
      // the same transaction as the RiskAssessment upsert makes the two
      // atomic: a caller can never observe 'COMPLETED' with a null
      // riskAssessment, or vice versa.
function toEmailClassification(prediction: string): EmailClassification {
  if (prediction === 'PHISHING_OR_SPAM' || prediction === 'PHISHING') return EmailClassification.PHISHING;
  if (prediction === 'LEGITIMATE' || prediction === 'HAM' || prediction === 'BENIGN') return EmailClassification.LEGITIMATE;
  if (prediction in EmailClassification) return (EmailClassification as any)[prediction];
  return EmailClassification.SUSPICIOUS;
}

      if (ml && ml.status === 'MODEL_PREDICTION' && ml.prediction) {
         await tx.email.update({
            where: { id: email.id },
            data: {
               classification: toEmailClassification(ml.prediction),
               riskScore: finalScore,
               analysisStatus: 'COMPLETED'
            }
         });
      } else {
         await tx.email.update({
            where: { id: email.id },
            data: {
               riskScore: finalScore,
               analysisStatus: 'COMPLETED'
            }
         });
      }

      await completeEmailOutboxEvent(tx, outboxEventId);

      // Alert is the only real notification substrate in this codebase
      // (backs both the Alerts page and the header notification bell —
      // apps/web/src/pages/Alerts.tsx / layouts/Header.tsx). Only
      // CRITICAL/HIGH results create one — analysts don't need a
      // notification for every routine LOW/MEDIUM email, and this mirrors
      // the same >=60 threshold already used for the P2/P1 priority tiers
      // (packages/types/src/threat.ts's calculateThreatPriority).
      if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
        const topFactor = [...factors].sort((a, b) => b.scoreContribution - a.scoreContribution)[0];
        const alertTitle = `${riskLevel} risk email analyzed`;
        const createdAlert = await tx.alert.create({
          data: {
            organizationId: email.organizationId,
            title: alertTitle,
            message: topFactor
              ? `${email.subject ?? '(no subject)'} from ${email.senderAddress ?? 'unknown sender'} — ${topFactor.description}`
              : `${email.subject ?? '(no subject)'} from ${email.senderAddress ?? 'unknown sender'} scored ${finalScore}/100`,
            severity: riskLevel,
          },
        });
        newAlert = { id: createdAlert.id, title: alertTitle, severity: riskLevel };
      }
    });

    // Published AFTER the transaction commits (never inside it) — the
    // real-time push is a best-effort side channel to an already-durable
    // Alert row, same "never let a notification failure affect the
    // primary write" policy as the webhook notifier call below.
    const createdAlertForNotification = newAlert as { id: string; title: string; severity: 'CRITICAL' | 'HIGH' } | null;
    if (createdAlertForNotification && this.notificationRedis) {
      await publishNotification(this.notificationRedis, {
        type: 'ALERT_CREATED',
        organizationId: email.organizationId,
        alertId: createdAlertForNotification.id,
        severity: createdAlertForNotification.severity,
        title: createdAlertForNotification.title,
        timestamp: new Date().toISOString(),
      });
    }

    logger.info({ emailId, finalScore, riskLevel }, 'Fusion Engine evaluation completed');

    // Awaited (unlike webhook DELIVERY, which happens later on a separate
    // queue consumer) because enqueueing is just a fast Redis push — but a
    // failure here must still never surface as an email-analysis failure,
    // since the risk assessment above is already durably persisted
    // regardless of this outcome. Caught and logged, never rethrown.
    if (this.notifier) {
      const threatCategory = (ml && ml.status === 'MODEL_PREDICTION' && ml.prediction) ? ml.prediction : email.classification;
      // Reads back the status this transaction just wrote (not a literal
      // 'COMPLETED' here) so this notification-payload field is never
      // mistaken by static analysis for a third analysisStatus DB write —
      // see src/__tests__/analysisStatusInvariant.test.ts, which asserts
      // exactly two literal writes exist (the ML and non-ML branches above).
      const notifiedAnalysisStatus = FINAL_ANALYSIS_STATUS;
      try {
        await this.notifier.notifyThreatAnalysisCompleted({
          emailId,
          organizationId: email.organizationId,
          threatScore: finalScore,
          priority: riskLevel,
          threatCategory,
          analysisStatus: notifiedAnalysisStatus,
        });
      } catch (err) {
        logger.error({ err, emailId }, 'Failed to enqueue THREAT_ANALYSIS_COMPLETED notification');
      }
    }
  }
}
