import type {
  EmailAnalysisSummary,
  EmailHeader,
  EmailRelayHop,
  EmailMimePart,
  EmailUrlEntry,
  EmailAttachmentEntry,
  EvidenceGraphResponse,
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
    /**
     * True when any DKIM signature cryptographically FAILed (Phase 8 —
     * real RFC 6376 verification). Deliberately NOT part of
     * `authenticationFailed` and NOT passed into calculateThreatPriority():
     * raw DKIM failures are materially noisier than SPF/DMARC hard-fails
     * (mailing lists and forwarders routinely break DKIM on legitimate
     * mail), so DKIM only affects priority indirectly, through DMARC
     * alignment (services/worker/src/verifier/DmarcVerifier.ts), which is
     * the RFC 7489-correct way to weigh it. This field is analyst-facing
     * visibility only, pending an explicit decision to fold it into scoring.
     */
    dkimFailed: boolean;
  };
  urls: EmailUrlEntry[];
  attachments: EmailAttachmentEntry[];
  indicators: ThreatIndicator[];
  cti: CtiResult[];
  geolocation: EmailGeolocationEntry[];
  evidenceGraph: EvidenceGraphResponse;
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
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  isp: string | null;
  /** Intelligence source, e.g. "MaxMind" — distinguishes a real provider
   *  result from the absence of one. */
  provider: string;
  /** When this record was last (re-)observed. */
  updatedAt: string;
}
