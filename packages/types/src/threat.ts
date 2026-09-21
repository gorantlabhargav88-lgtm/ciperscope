/**
 * Threat scoring, indicators, and the P1/P2/P3 priority model.
 *
 * ============================================================================
 * SEVERITY vs THREAT SCORE vs PRIORITY — these are three distinct concepts.
 * ============================================================================
 *
 * - Severity ("Priority" in the Prisma schema — see
 *   packages/database/prisma/schema.prisma `enum Priority` / `RiskAssessment.riskLevel`):
 *   the NATURE/SERIOUSNESS of what was detected. Backend vocabulary is
 *   LOW | MEDIUM | HIGH | CRITICAL. This enum is NOT being replaced or renamed.
 *
 * - Threat Score (`RiskAssessment.overallScore`): a quantitative 0-100 risk
 *   signal computed by the backend's FusionEngine
 *   (services/worker/src/analyzer/FusionEngine.ts) from real, explainable
 *   RiskFactor rows.
 *
 * - Priority (P1/P2/P3, defined here): OPERATIONAL URGENCY for analyst
 *   response. This concept does not exist anywhere in the backend today —
 *   it is a new, deliberately-designed application-layer classification
 *   computed from severity + threat score + corroborating security signals
 *   (CTI verdicts, authentication failures, ML classification). It is NOT a
 *   1:1 rename of severity: a CRITICAL-severity email with no corroborating
 *   signal resolves to a lower priority than one confirmed by CTI and failed
 *   authentication.
 *
 * This is CiperScope's own deterministic OPERATIONAL PRIORITIZATION POLICY.
 * It is not a scientifically validated risk model, and it must not be
 * presented to users as one.
 */

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatPriority = 'P1' | 'P2' | 'P3';

export interface ThreatScoreFactor {
  category: string;
  description: string;
  scoreContribution: number;
}

/** Derived from Email.riskScore / RiskAssessment — never fabricated; absent fields mean no data. */
export interface ThreatScore {
  value: number | null;
  severity: Severity | null;
  factors: ThreatScoreFactor[];
}

export type ThreatVerdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

/** Maps to the objects returned by GET /emails/:emailId/threat-indicators */
export interface ThreatIndicator {
  id: string;
  iocType: string;
  iocValue: string;
  provider: string;
  status: ThreatVerdict;
  confidence: number | null;
}

/**
 * Inputs to the priority calculation. All fields must come from real,
 * already-computed backend data — never fabricate a signal that has no
 * underlying evidence.
 */
export interface ThreatPrioritySignals {
  /** RiskAssessment.riskLevel. Use null when no risk assessment exists yet. */
  severity: Severity | null;
  /** RiskAssessment.overallScore (0-100). Use null when no risk assessment exists yet. */
  threatScore: number | null;
  /** Count of ThreatIndicator entries with status MALICIOUS or SUSPICIOUS. */
  maliciousIndicatorCount: number;
  /**
   * True when SPF or DMARC evaluated to FAIL. DKIM is deliberately excluded
   * from this specific signal — not because it isn't real (DKIM performs
   * genuine RFC 6376 cryptographic verification, see authentication.ts), but
   * because raw DKIM failures are materially noisier than SPF/DMARC
   * hard-fails: mailing lists and forwarders routinely break DKIM signatures
   * on entirely legitimate mail. DKIM already affects this indirectly
   * through DMARC alignment (services/worker/src/verifier/DmarcVerifier.ts),
   * which is the RFC 7489-correct way to weigh it. Raw DKIM pass/fail is
   * still surfaced to analysts as a separate, non-scoring signal — see
   * EmailForensicsData['threat']['dkimFailed'] in email-forensics.ts.
   */
  authenticationFailed: boolean;
  /** MLInference.prediction, when available (e.g. PHISHING, BEC, MALWARE). */
  mlClassification?: string | null;
}

export interface ThreatPriorityResult {
  priority: ThreatPriority;
  /** Human-readable justification, for display next to the P1/P2/P3 badge — never hidden from the analyst. */
  reasons: string[];
}

const ML_MALICIOUS_CLASSIFICATIONS = new Set(['PHISHING', 'BEC', 'MALWARE', 'FRAUD', 'IMPERSONATION']);

/**
 * CiperScope Threat Priority calculation (deterministic, pure, documented
 * operational policy — see module doc comment above).
 *
 * Rules, evaluated in order, first match wins:
 *   1. P1 — threat score >= 90 (an extreme score alone always overrides to P1).
 *   2. P1 — CRITICAL severity AND at least one corroborating signal
 *      (score >= 80, OR a malicious/suspicious indicator, OR a malicious ML
 *      classification). CRITICAL severity alone is not sufficient for P1.
 *   3. P2 — HIGH or CRITICAL severity, or threat score >= 60.
 *   4. P2 — authentication failed (SPF/DMARC) AND at least one malicious/
 *      suspicious indicator, regardless of severity/score.
 *   5. P3 — everything else, including cases with no risk assessment yet
 *      (severity/threatScore null defaults to the lowest urgency until real
 *      data exists — never guess).
 */
export function calculateThreatPriority(signals: ThreatPrioritySignals): ThreatPriorityResult {
  const severity = signals.severity;
  const threatScore = signals.threatScore ?? 0;
  const maliciousIndicatorCount = signals.maliciousIndicatorCount;
  const authenticationFailed = signals.authenticationFailed;
  const mlClassification = signals.mlClassification ?? null;
  const mlFlaggedMalicious = mlClassification !== null && ML_MALICIOUS_CLASSIFICATIONS.has(mlClassification);

  if (threatScore >= 90) {
    return {
      priority: 'P1',
      reasons: [`Threat score ${threatScore} meets the P1 override threshold (>= 90)`],
    };
  }

  if (severity === 'CRITICAL' && (threatScore >= 80 || maliciousIndicatorCount > 0 || mlFlaggedMalicious)) {
    const corroboration = [
      threatScore >= 80 ? `threat score ${threatScore}` : null,
      maliciousIndicatorCount > 0 ? `${maliciousIndicatorCount} malicious/suspicious indicator(s)` : null,
      mlFlaggedMalicious ? `ML classification "${mlClassification}"` : null,
    ].filter((x): x is string => x !== null);
    return {
      priority: 'P1',
      reasons: [`CRITICAL severity corroborated by ${corroboration.join(', ')}`],
    };
  }

  if (severity === 'HIGH' || severity === 'CRITICAL' || threatScore >= 60) {
    return {
      priority: 'P2',
      reasons: [`Severity ${severity ?? 'UNKNOWN'} with threat score ${threatScore}`],
    };
  }

  if (authenticationFailed && maliciousIndicatorCount > 0) {
    return {
      priority: 'P2',
      reasons: [
        `Authentication failure (SPF/DMARC) combined with ${maliciousIndicatorCount} malicious/suspicious indicator(s)`,
      ],
    };
  }

  return {
    priority: 'P3',
    reasons: [`Severity ${severity ?? 'UNKNOWN'} with threat score ${threatScore} and no corroborating signals`],
  };
}
