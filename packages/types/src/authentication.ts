/**
 * SPF / DKIM / DMARC contracts.
 *
 * Backend mapping: services/api's /emails/:emailId/{spf,dkim,dmarc,authentication}
 * endpoints return raw Prisma SpfVerification/DkimVerification/DmarcVerification/
 * EmailAuthenticationAnalysis rows. Field names are kept as-is (result, domain,
 * explanation, ...) since renaming them here would provide no contract benefit.
 *
 * IMPORTANT — DKIM honesty requirement (Phase 8, see
 * services/worker/src/verifier/DkimVerifier.ts and
 * services/worker/src/verifier/dkim/verifyCryptography.ts): DKIM verification
 * performs real RFC 6376 cryptographic signature verification (body hash +
 * header signature, via Node's crypto module, against the DNS-retrieved
 * public key). `DkimResult.cryptographicallyVerified` is derived at the
 * api-client layer as `result === 'PASS'` (packages/api-client/src/client.ts)
 * — the backend's `result` field can only be `'PASS'` when that cryptographic
 * verification actually succeeded, never from signature presence, length, or
 * syntactic validity alone. This field remains the single place the UI should
 * check before ever displaying a DKIM result as trustworthy.
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
  /** True only when `result === 'PASS'` — i.e. only after a real RFC 6376 cryptographic verification succeeded. */
  cryptographicallyVerified: boolean;
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
