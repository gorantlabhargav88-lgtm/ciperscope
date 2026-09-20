import type { Severity, ThreatPriorityResult } from './threat';
import type { ChainOfCustodyActor } from './evidence';

/**
 * Unified forensic timeline event contract.
 *
 * Backend mapping: GET /cases/:caseId/forensic-timeline
 * (services/api/src/modules/case/case.routes.ts). Unlike the plain
 * `/cases/:caseId/timeline` endpoint (raw `AuditLog` rows scoped to
 * `resource: 'Case'` — see caseTimeline.ts), this endpoint correlates
 * REAL persisted records across Case, Email, EmailAuthenticationAnalysis,
 * RiskAssessment, MLInference, Indicator/ThreatIntelObservation,
 * Investigation, Evidence, ChainOfCustodyEvent, and the analyst-decision
 * AuditLog trail — using each record's own timestamp as the event time,
 * since the background worker does not write AuditLog entries for
 * forensic processing steps (confirmed by repository-wide search).
 *
 * Every field here is backed by a real column/relation. Nothing is
 * synthesized to fill a gap — if a signal doesn't exist, the corresponding
 * event category simply does not appear.
 */
export type ForensicTimelineCategory =
  | 'EMAIL'
  | 'AUTHENTICATION'
  | 'THREAT_INTELLIGENCE'
  | 'ML'
  | 'INVESTIGATION'
  | 'EVIDENCE'
  | 'ANALYST'
  | 'SYSTEM';

export interface ForensicTimelineEvent {
  id: string;
  /** ISO timestamp from the underlying record's own createdAt/observationTime/timestamp/collectionTime field. Null only if genuinely absent. */
  timestamp: string | null;
  category: ForensicTimelineCategory;
  /** Raw action/event code (e.g. 'EMAIL_INGESTED', 'CASE_INVESTIGATION_DECISION_RECORDED', a CustodyAction, or an Indicator verdict-derived code). */
  action: string;
  title: string;
  description: string | null;
  /** Only set for events tied to a specific email's RiskAssessment.riskLevel. */
  severity: Severity | null;
  /** Only set for events tied to a specific email, computed via the shared calculateThreatPriority() — never a second algorithm. */
  priority: ThreatPriorityResult | null;
  /** Real provenance, e.g. a CTI provider name, 'CiperScope FusionEngine', or a DistilBERT model name. Null when not applicable. */
  source: string | null;
  resourceType: 'Case' | 'Email' | 'Investigation' | 'Evidence' | 'Indicator' | 'AuditLog';
  resourceId: string;
  caseId: string;
  emailId: string | null;
  investigationId: string | null;
  evidenceId: string | null;
  actor: ChainOfCustodyActor | null;
  metadata: Record<string, unknown> | null;
}
