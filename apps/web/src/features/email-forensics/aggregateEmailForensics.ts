import { apiClient } from '../../lib/apiClient';
import { calculateThreatPriority } from '@ciperscope/types';
import type {
  EmailForensicsData,
  CtiResult,
  TimelineEvent,
  CaseSummary,
  InvestigationSummary,
} from '@ciperscope/types';

/**
 * Composes the existing, already-real email-forensics endpoints
 * (services/api/src/modules/email/email.routes.ts) into one coherent
 * EmailForensicsData object. This function does not duplicate any
 * threat-analysis or database logic — it only calls the typed API client
 * and shapes the results.
 *
 * `caseIdOverride` lets a caller that already knows a different case
 * context force it (rare); by default the real `caseId` now comes from
 * GET /emails/:emailId/analysis (Phase 3, Step 2 — previously a documented
 * missing backend capability). When the email genuinely isn't linked to a
 * case yet (`caseId` is `null`), `evidence` and `investigationContext` are
 * honestly `null` rather than guessed at.
 */
export async function aggregateEmailForensics(
  emailId: string,
  caseIdOverride?: string | null
): Promise<EmailForensicsData> {
  const [
    email,
    headersRes,
    hopsRes,
    mimePartsRes,
    authSummaryRes,
    spfRes,
    dkimRes,
    dmarcRes,
    urlsRes,
    attachmentsRes,
    aiAnalysisRes,
    threatIndicatorsRes,
    geolocationRes,
  ] = await Promise.all([
    apiClient.getEmailAnalysis(emailId),
    apiClient.getEmailHeaders(emailId),
    apiClient.getEmailReceivedHops(emailId),
    apiClient.getEmailMimeParts(emailId),
    apiClient.getEmailAuthenticationSummary(emailId),
    apiClient.getEmailSpf(emailId),
    apiClient.getEmailDkim(emailId),
    apiClient.getEmailDmarc(emailId),
    apiClient.getEmailUrls(emailId),
    apiClient.getEmailAttachments(emailId),
    apiClient.getEmailAiAnalysis(emailId),
    apiClient.getEmailThreatIndicators(emailId),
    apiClient.getEmailGeolocation(emailId),
  ]);

  const maliciousIndicatorCount = threatIndicatorsRes.threatIndicators.filter(
    (i) => i.status === 'MALICIOUS' || i.status === 'SUSPICIOUS'
  ).length;

  const authenticationFailed =
    spfRes.spfVerifications.some((s) => s.result === 'FAIL') || dmarcRes.dmarcVerification?.result === 'FAIL';

  const mlPrediction = aiAnalysisRes.prediction;
  const mlStatus = aiAnalysisRes.status ?? mlPrediction?.status ?? null;
  const mlClassification = mlStatus === 'NOT_AVAILABLE' ? null : (mlPrediction?.prediction ?? null);

  const riskAssessment = email.riskAssessment;
  const priority = calculateThreatPriority({
    severity: riskAssessment?.riskLevel ?? null,
    threatScore: riskAssessment?.overallScore ?? email.riskScore ?? null,
    maliciousIndicatorCount,
    authenticationFailed,
    mlClassification,
  });

  // CTI results are derived from the same persisted ThreatIntelObservation
  // data as threat-indicators — CiperScope has no separate per-email CTI
  // endpoint distinct from /threat-indicators (see packages/types/src/cti.ts).
  const cti: CtiResult[] = threatIndicatorsRes.threatIndicators.map((indicator) => ({
    indicatorType: indicator.iocType,
    indicatorValue: indicator.iocValue,
    provider: indicator.provider,
    verdict: indicator.status,
    confidence: indicator.confidence,
    status: 'ok',
  }));

  const timeline: TimelineEvent[] = [];
  if (email.createdAt) {
    timeline.push({ id: 'ingested', type: 'EMAIL_INGESTED', timestamp: email.createdAt, title: 'Email ingested' });
  }
  if (authSummaryRes.analysis) {
    timeline.push({
      id: 'auth',
      type: 'AUTHENTICATION_CHECKED',
      timestamp: email.createdAt,
      title: 'SPF/DKIM/DMARC checked',
      description: authSummaryRes.analysis.summary ?? undefined,
    });
  }
  if (riskAssessment) {
    timeline.push({
      id: 'risk',
      type: 'THREAT_ANALYZED',
      timestamp: email.createdAt,
      title: `Threat analysis completed (score ${riskAssessment.overallScore})`,
      severity: riskAssessment.riskLevel,
    });
  }
  if (mlStatus && mlStatus !== 'NOT_AVAILABLE') {
    timeline.push({
      id: 'ml',
      type: 'ML_CLASSIFIED',
      timestamp: email.createdAt,
      title: `ML classification: ${mlClassification ?? 'unknown'}`,
    });
  }
  if (threatIndicatorsRes.threatIndicators.length > 0) {
    timeline.push({
      id: 'cti',
      type: 'CTI_ENRICHED',
      timestamp: email.createdAt,
      title: `${threatIndicatorsRes.threatIndicators.length} threat indicator(s) found`,
    });
  }

  const caseId = caseIdOverride ?? email.caseId;

  let evidence: EmailForensicsData['evidence'] = null;
  let investigationContext: EmailForensicsData['investigationContext'] = null;
  if (caseId) {
    const [caseDetail, evidenceList, investigations] = await Promise.all([
      apiClient.getCase(caseId).catch(() => null as CaseSummary | null),
      apiClient.getCaseEvidenceList(caseId).catch(() => null),
      apiClient.getCaseInvestigations(caseId).catch(() => null as { items: InvestigationSummary[] } | null),
    ]);
    evidence = evidenceList?.items ?? null;
    investigationContext = {
      case: caseDetail,
      investigations: investigations?.items ?? [],
    };
  }

  return {
    email,
    headers: headersRes.headers,
    relayHops: hopsRes.hops,
    mimeParts: mimePartsRes.mimeParts,
    authentication: {
      summary: authSummaryRes.analysis,
      spf: spfRes.spfVerifications,
      dkim: dkimRes.dkimVerifications,
      dmarc: dmarcRes.dmarcVerification,
    },
    threat: {
      score: {
        value: riskAssessment?.overallScore ?? email.riskScore ?? null,
        severity: riskAssessment?.riskLevel ?? null,
        factors: riskAssessment?.factors ?? [],
      },
      priority,
      mlClassification,
      mlStatus,
      maliciousIndicatorCount,
      authenticationFailed,
    },
    urls: urlsRes.urls,
    attachments: attachmentsRes.attachments,
    indicators: threatIndicatorsRes.threatIndicators,
    cti,
    geolocation: geolocationRes.geolocation,
    evidence,
    timeline,
    investigationContext,
  };
}
