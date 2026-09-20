/**
 * SPF / DKIM / DMARC contracts.
 *
 * Backend mapping: services/api's /emails/:emailId/{spf,dkim,dmarc,authentication}
 * endpoints return raw Prisma SpfVerification/DkimVerification/DmarcVerification/
 * EmailAuthenticationAnalysis rows. Field names are kept as-is (result, domain,
 * explanation, ...) since renaming them here would provide no contract benefit.
 *
 * IMPORTANT — DKIM honesty requirement (see CIPERSCOPE_NEXT_PHASE_AUDIT.md and
 * services/worker/src/verifier/DkimVerifier.ts:67-110): CiperScope's DKIM
 * "verification" is a length-based simulation, not real cryptographic
 * signature verification. `DkimResult.cryptographicallyVerified` is always
 * `false` today so the UI has a single, impossible-to-forget place to check
 * before ever displaying a DKIM result as trustworthy.
 */

export type AuthResultStatus =
  | 'PASS'
  | 'FAIL'
  | 'SOFTFAIL'
  | 'NEUTRAL'
  | 'NONE'
  | 'TEMPERROR'
  | 'PERMERROR';

const VALID_AUTH_RESULT_STATUSES: ReadonlySet<string> = new Set<AuthResultStatus>([
  'PASS',
  'FAIL',
  'SOFTFAIL',
  'NEUTRAL',
  'NONE',
  'TEMPERROR',
  'PERMERROR',
]);

/**
 * Normalizes an SPF/DKIM/DMARC result string to the backend's real
 * `AuthResultStatus` enum, tolerating case differences
 * (services/api returns uppercase e.g. `'PASS'`, but some UI code —
 * see apps/web/src/components/ForensicTimeline.tsx — historically compared
 * against lowercase `'pass'` and silently never matched). `'UNKNOWN'` is a
 * UI-only fallback for missing/malformed data — it is never a real backend
 * value, so callers must not treat it as one of the seven real statuses.
 */
export function normalizeAuthResult(result: string | null | undefined): AuthResultStatus | 'UNKNOWN' {
  if (!result) return 'UNKNOWN';
  const upper = result.toUpperCase();
  return VALID_AUTH_RESULT_STATUSES.has(upper) ? (upper as AuthResultStatus) : 'UNKNOWN';
}

export function isAuthResultPass(result: string | null | undefined): boolean {
  return normalizeAuthResult(result) === 'PASS';
}

export interface SpfResult {
  result: AuthResultStatus;
  domain: string | null;
  evaluatedIp: string | null;
  matchedMechanism: string | null;
  explanation: string | null;
}

export interface DkimResult {
  result: AuthResultStatus;
  domain: string | null;
  selector: string | null;
  explanation: string | null;
  /** Always false — CiperScope does not perform real cryptographic DKIM verification yet. */
  cryptographicallyVerified: false;
}

export interface DmarcResult {
  result: AuthResultStatus;
  orgDomain: string | null;
  policy: string | null;
  subdomainPolicy: string | null;
  spfAlignment: string | null;
  dkimAlignment: string | null;
  explanation: string | null;
}

/** GET /emails/:emailId/authentication -> { analysis: EmailAuthenticationSummary | null } */
export interface EmailAuthenticationSummary {
  spf: AuthResultStatus;
  dkim: AuthResultStatus;
  dmarc: AuthResultStatus;
  isConsistent: boolean;
  summary: string | null;
}

/** Composed view used by the Email Forensics aggregator (packages/types/src/email.ts consumers) */
export interface EmailAuthentication {
  summary: EmailAuthenticationSummary | null;
  spf: SpfResult[];
  dkim: DkimResult[];
  dmarc: DmarcResult | null;
}
