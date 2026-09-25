/**
 * Org-wide Indicators of Compromise — GET /intelligence/indicators
 * (services/api/src/modules/intelligence/intelligence.routes.ts). Reuses
 * the same Indicator/ThreatIntelObservation tables as the per-email
 * GET /emails/:emailId/threat-indicators endpoint (see ThreatIndicator in
 * threat.ts), aggregated across every email this organization has ever
 * ingested — never a second indicator model.
 */
export type IndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL_ADDRESS';

export type IndicatorSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IndicatorReputation = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface IndicatorCtiObservation {
  id: string;
  provider: string;
  verdict: IndicatorReputation;
  confidence: number | null;
  observationTime: string;
}

export interface OrgIndicator {
  type: IndicatorType;
  value: string;
  /** CTI provider of the most recent observation, when one exists. */
  source: string | null;
  /** Derived from the latest CTI verdict — null when no CTI observation exists for this value yet. */
  severity: IndicatorSeverity | null;
  confidence: number | null;
  reputation: IndicatorReputation;
  firstSeen: string;
  lastSeen: string;
  relatedEmailCount: number;
  relatedCaseCount: number;
  relatedEmailIds: string[];
  extractionSources: string[];
  cti: { indicatorId: string; observations: IndicatorCtiObservation[] } | null;
  createdAt: string;
}

export interface OrgIndicatorListResponse {
  items: OrgIndicator[];
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  /** True when the underlying bounded aggregation hit a read cap — the list may be an undercount. */
  truncated: boolean;
}
