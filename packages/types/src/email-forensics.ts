import type {
  EmailAnalysisSummary,
  EmailHeader,
  EmailRelayHop,
  EmailMimePart,
  EmailUrlEntry,
  EmailAttachmentEntry,
} from './email';
import type { EmailAuthentication } from './authentication';
import type { ThreatScore, ThreatIndicator, ThreatPriorityResult } from './threat';
import type { CtiResult } from './cti';
import type { Evidence } from './evidence';
import type { TimelineEvent } from './timeline';
import type { CaseSummary, InvestigationSummary } from './investigation';

/**
 * The composed shape produced by the Email Forensics data aggregator
 * (apps/web/src/features/email-forensics/aggregateEmailForensics.ts).
 * This type only COMPOSES data already returned by existing endpoints —
 * it does not represent a new backend response.
 */
export interface EmailForensicsData {
  email: EmailAnalysisSummary;
  headers: EmailHeader[];
  relayHops: EmailRelayHop[];
  mimeParts: EmailMimePart[];
  authentication: EmailAuthentication;
  threat: {
    score: ThreatScore;
    priority: ThreatPriorityResult;
    mlClassification: string | null;
    mlStatus: string | null;
    /** Same signals passed into calculateThreatPriority() — exposed so the UI never recomputes or duplicates the priority logic. */
    maliciousIndicatorCount: number;
    authenticationFailed: boolean;
  };
  urls: EmailUrlEntry[];
  attachments: EmailAttachmentEntry[];
  indicators: ThreatIndicator[];
  cti: CtiResult[];
  geolocation: EmailGeolocationEntry[];
  /** Present only when the email's case is already known to the caller (see MISSING BACKEND CAPABILITY note in email.ts). */
  evidence: Evidence[] | null;
  timeline: TimelineEvent[];
  investigationContext: {
    case: CaseSummary | null;
    investigations: InvestigationSummary[];
  } | null;
}

/** GET /emails/:emailId/geolocation */
export interface EmailGeolocationEntry {
  ipAddress: string;
  country: string | null;
  city: string | null;
  asn: string | null;
  isp: string | null;
}
