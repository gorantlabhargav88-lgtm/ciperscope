import { prisma } from '@ciperscope/database';

// Bounded reads per source table — same "read-only, already-persisted,
// bounded" pattern as intelligence.routes.ts's RELAY_HOP_CAP and
// case.routes.ts's forensic-timeline EVENT_CAP. This is a demo/mid-scale
// deployment safety limit, not a pagination contract.
const URL_CAP = 5000;
const ATTACHMENT_CAP = 5000;
const RELAY_HOP_CAP = 5000;
const ADDRESS_CAP = 5000;

export type AggregatedIndicatorType = 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL_ADDRESS';

export interface AggregatedIndicator {
  type: AggregatedIndicatorType;
  value: string;
  firstSeen: Date;
  lastSeen: Date;
  emailIds: Set<string>;
  /** URL extraction sources this value was seen with (TEXT, HTML_HREF, QR_CODE, ...) — informational only. */
  extractionSources: Set<string>;
}

export interface OrgIndicatorAggregation {
  /** Deduplicated by `${type}:${value}`. */
  indicators: AggregatedIndicator[];
  /** True when any single source table hit its read cap — the result may be an undercount. */
  truncated: boolean;
}

/**
 * Aggregates the organization's already-persisted IOC-bearing rows
 * (EmailUrl, EmailAttachment.sha256, RelayHop.sourceIp, EmailAddress) into
 * one deduplicated indicator set, generalizing the per-email pattern in
 * email.routes.ts's GET /:emailId/threat-indicators to the whole
 * organization. Never queries an external threat-intel provider itself —
 * enrichment (ThreatIntelObservation) is looked up separately by the caller
 * against the existing global Indicator/ThreatIntelObservation tables.
 *
 * QR-code-decoded URLs are NOT a separate indicator type here: per
 * EmailAttachment.qrFindings's own schema comment, decoded QR URLs are
 * already persisted as ordinary EmailUrl rows (source QR_CODE), so they
 * flow through this same URL aggregation unchanged. Likewise APK files are
 * just EmailAttachment rows — their sha256 is aggregated as a HASH
 * indicator like any other attachment.
 *
 * `since`, when provided, bounds every source query to rows created at or
 * after that time (used by the analytics endpoint's date-range selector).
 * Omit it for the full, all-time indicator set (used by the org-wide
 * Indicators page).
 */
export async function aggregateOrgIndicators(
  organizationId: string,
  since?: Date
): Promise<OrgIndicatorAggregation> {
  const createdAtFilter = since ? { createdAt: { gte: since } } : {};

  const [urls, attachments, relayHops, addresses] = await Promise.all([
    prisma.emailUrl.findMany({
      where: { email: { organizationId }, ...createdAtFilter },
      select: { url: true, normalizedUrl: true, domain: true, source: true, createdAt: true, emailId: true },
      take: URL_CAP,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.emailAttachment.findMany({
      where: { email: { organizationId }, ...createdAtFilter, sha256: { not: null } },
      select: { sha256: true, createdAt: true, emailId: true },
      take: ATTACHMENT_CAP,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.relayHop.findMany({
      where: { email: { organizationId }, ...createdAtFilter, sourceIp: { not: null } },
      select: { sourceIp: true, createdAt: true, emailId: true },
      take: RELAY_HOP_CAP,
      orderBy: { createdAt: 'desc' },
    }),
    prisma.emailAddress.findMany({
      where: { email: { organizationId }, ...createdAtFilter, headerName: 'From', address: { not: null } },
      select: { address: true, createdAt: true, emailId: true },
      take: ADDRESS_CAP,
      orderBy: { createdAt: 'desc' },
    }),
  ]);

  const byKey = new Map<string, AggregatedIndicator>();

  const upsert = (
    type: AggregatedIndicatorType,
    value: string | null | undefined,
    createdAt: Date,
    emailId: string,
    extractionSource?: string
  ) => {
    if (!value) return;
    const key = `${type}:${value}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.emailIds.add(emailId);
      if (extractionSource) existing.extractionSources.add(extractionSource);
      if (createdAt < existing.firstSeen) existing.firstSeen = createdAt;
      if (createdAt > existing.lastSeen) existing.lastSeen = createdAt;
    } else {
      byKey.set(key, {
        type,
        value,
        firstSeen: createdAt,
        lastSeen: createdAt,
        emailIds: new Set([emailId]),
        extractionSources: new Set(extractionSource ? [extractionSource] : []),
      });
    }
  };

  for (const u of urls) {
    upsert('URL', u.normalizedUrl ?? u.url, u.createdAt, u.emailId, u.source);
    upsert('DOMAIN', u.domain, u.createdAt, u.emailId);
  }
  for (const a of attachments) {
    upsert('HASH', a.sha256, a.createdAt, a.emailId);
  }
  for (const h of relayHops) {
    upsert('IP', h.sourceIp, h.createdAt, h.emailId);
  }
  for (const addr of addresses) {
    upsert('EMAIL_ADDRESS', addr.address, addr.createdAt, addr.emailId);
  }

  return {
    indicators: Array.from(byKey.values()),
    truncated:
      urls.length >= URL_CAP ||
      attachments.length >= ATTACHMENT_CAP ||
      relayHops.length >= RELAY_HOP_CAP ||
      addresses.length >= ADDRESS_CAP,
  };
}

/** Deterministic, documented policy — same style as ThreatPriority in packages/types/src/threat.ts. */
export function severityFromVerdict(verdict: string | null | undefined): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | null {
  switch (verdict) {
    case 'MALICIOUS':
      return 'CRITICAL';
    case 'SUSPICIOUS':
      return 'MEDIUM';
    case 'CLEAN':
      return 'LOW';
    default:
      return null;
  }
}
