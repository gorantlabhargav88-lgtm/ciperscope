import type { Severity } from './threat';

/**
 * Case/Investigation contracts, scoped to what the Email Forensics slice and
 * InvestigationWorkspace need. Backend mapping:
 * services/api/src/modules/case/case.routes.ts — GET /:caseId,
 * GET /:caseId/investigations, GET /:caseId/investigations/:investigationId,
 * GET /:caseId/investigations/:investigationId/intelligence,
 * GET /:caseId/investigations/:investigationId/workspace,
 * GET/POST /:caseId/investigations/:investigationId/decisions.
 */

export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

/**
 * Backend mapping note: GET /:caseId (used by ApiClient.getCase) does not
 * select `severity` — only the richer /:caseId/investigations/:id/workspace
 * endpoint does. `severity` is therefore optional here rather than
 * pretending every case response includes it.
 */
export interface CaseSummary {
  id: string;
  organizationId: string;
  title: string;
  description: string | null;
  status: CaseStatus;
  severity?: Severity;
  priority: Severity;
  assignedUserId: string | null;
  creatorId: string;
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

export interface InvestigationSummary {
  id: string;
  caseId: string;
  title: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface InvestigationRiskSummary {
  maximumRiskScore: number;
  averageRiskScore: number;
  highRiskCount: number;
  severityDistribution: Record<string, number>;
  classificationDistribution: Record<string, number>;
  entityCounts: {
    emails: number;
    evidence: number;
    alerts: number;
    reports: number;
  };
}

export interface InvestigationCorrelation {
  type: string;
  sourceId: string;
  targetId: string;
  confidence: number;
  reasons: string[];
}

export interface InvestigationAttentionIndicator {
  type: string;
  severity: string;
  message: string;
  relatedIds?: string[];
}

/** GET /:caseId/investigations/:investigationId/intelligence */
export interface InvestigationIntelligence {
  investigation: InvestigationSummary;
  riskSummary: InvestigationRiskSummary;
  correlations: InvestigationCorrelation[];
  attentionIndicators: InvestigationAttentionIndicator[];
}

export type AnalystDecisionType = 'REVIEWED' | 'CONFIRMED' | 'DISMISSED' | 'ESCALATED';

/** POST/GET /:caseId/investigations/:investigationId/decisions */
export interface AnalystDecision {
  id?: string;
  targetId: string;
  targetType: string;
  decision: AnalystDecisionType;
  reason?: string;
  actorId?: string;
  createdAt?: string;
}
