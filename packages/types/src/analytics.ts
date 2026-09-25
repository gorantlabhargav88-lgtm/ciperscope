/**
 * Org-wide Security Analytics — GET /analytics/overview
 * (services/api/src/modules/analytics/analytics.routes.ts). Every field is
 * computed from already-persisted rows for the requesting organization
 * within the selected date range; nothing here is fabricated or estimated.
 */
export type AnalyticsRange = '24h' | '7d' | '30d' | '90d';

export interface AnalyticsSeverityCount {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  count: number;
}

export interface AnalyticsCaseStatusCount {
  status: string;
  count: number;
}

export interface AnalyticsCasePriorityCount {
  priority: string;
  count: number;
}

export interface AnalyticsIndicatorTypeCount {
  type: string;
  count: number;
}

export interface AnalyticsThreatActivityBucket {
  /** Hourly (yyyy-mm-ddThh) for the 24h range, daily (yyyy-mm-dd) otherwise. */
  bucket: string;
  total: number;
  threats: number;
}

export interface AnalyticsTopDomain {
  domain: string;
  count: number;
}

export interface AnalyticsTopIp {
  ip: string;
  count: number;
}

export interface AnalyticsOverview {
  range: AnalyticsRange;
  since: string;
  emailsAnalyzed: number;
  threatsDetected: number;
  criticalThreats: number;
  openCriticalCases: number;
  maliciousUrls: number;
  suspiciousAttachments: number;
  apkDetections: number;
  qrDetections: number;
  uniqueIpIndicators: number;
  uniqueDomainIndicators: number;
  ctiObservations: number;
  severityDistribution: AnalyticsSeverityCount[];
  casesByStatus: AnalyticsCaseStatusCount[];
  casesByPriority: AnalyticsCasePriorityCount[];
  indicatorTypeDistribution: AnalyticsIndicatorTypeCount[];
  threatActivity: AnalyticsThreatActivityBucket[];
  topDomains: AnalyticsTopDomain[];
  topIps: AnalyticsTopIp[];
  truncated: boolean;
}
