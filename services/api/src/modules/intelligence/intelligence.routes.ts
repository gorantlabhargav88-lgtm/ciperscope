import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { classifyIp } from '@ciperscope/http-client';
import { env } from '@ciperscope/config';
import { logAuditEvent } from '../../utils/audit';
import { buildReverseDnsByIp } from '../email/email.routes';
import { aggregateOrgIndicators, severityFromVerdict } from './indicatorAggregation';
import { fastifyIndicatorListQuerySchema } from '../../utils/validation';

// Bounds the aggregation query — same "read-only, already-persisted,
// bounded" pattern as case.routes.ts's forensic-timeline EVENT_CAP. This
// is a demo/mid-scale-deployment safety limit, not a pagination contract.
const RELAY_HOP_CAP = 2000;
const RELATED_EMAILS_PER_IP_CAP = 5;

/**
 * Org-wide network intelligence — aggregates RelayHop rows (tenant-scoped
 * via Email.organizationId) with the existing, already-persisted
 * GeoLocation/DnsObservation(PTR) data. Never queries an external
 * GeoIP/DNS provider itself; this is a read of already-collected evidence,
 * generalizing the per-email pattern in email.routes.ts's
 * /:emailId/geolocation and /:emailId/intelligence to the whole
 * organization. Backs both the Geo Intelligence and Infrastructure
 * frontend pages — they render the same aggregated IP records with a
 * different focus (map/location vs. hop/ASN table), so one endpoint
 * avoids duplicating this query.
 */
export default async function intelligenceRoutes(server: FastifyInstance) {
  server.get('/network', {
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const relayHops = await prisma.relayHop.findMany({
      where: { email: { organizationId } },
      select: { sourceIp: true, hostname: true, emailId: true, hopOrder: true, timestamp: true, createdAt: true },
      take: RELAY_HOP_CAP,
      orderBy: { createdAt: 'desc' },
    });

    type Agg = {
      ip: string;
      hopCount: number;
      firstSeen: Date;
      lastSeen: Date;
      emailIds: Set<string>;
      hostnames: Set<string>;
    };
    const byIp = new Map<string, Agg>();
    for (const hop of relayHops) {
      if (!hop.sourceIp) continue;
      const seenAt = hop.timestamp ?? hop.createdAt;
      const existing = byIp.get(hop.sourceIp);
      if (existing) {
        existing.hopCount += 1;
        existing.emailIds.add(hop.emailId);
        if (hop.hostname) existing.hostnames.add(hop.hostname);
        if (seenAt < existing.firstSeen) existing.firstSeen = seenAt;
        if (seenAt > existing.lastSeen) existing.lastSeen = seenAt;
      } else {
        byIp.set(hop.sourceIp, {
          ip: hop.sourceIp,
          hopCount: 1,
          firstSeen: seenAt,
          lastSeen: seenAt,
          emailIds: new Set([hop.emailId]),
          hostnames: new Set(hop.hostname ? [hop.hostname] : []),
        });
      }
    }

    const uniqueIps = Array.from(byIp.keys());

    const [geoRows, ptrRows] = await Promise.all([
      uniqueIps.length > 0
        ? prisma.geoLocation.findMany({ where: { ipAddress: { in: uniqueIps } } })
        : Promise.resolve([]),
      uniqueIps.length > 0
        ? prisma.dnsObservation.findMany({
            where: { recordType: 'PTR', queryName: { in: uniqueIps }, email: { organizationId } },
            orderBy: { createdAt: 'desc' },
          })
        : Promise.resolve([]),
    ]);
    const geoByIp = new Map(geoRows.map((g) => [g.ipAddress, g]));
    const reverseDnsByIp = buildReverseDnsByIp(ptrRows);

    const items = uniqueIps.map((ip) => {
      const agg = byIp.get(ip)!;
      const classification = classifyIp(ip);
      const geo = geoByIp.get(ip) ?? null;
      return {
        ip,
        version: classification.version,
        classification: classification.category,
        isRoutablePublic: classification.isRoutablePublic,
        hopCount: agg.hopCount,
        firstSeen: agg.firstSeen,
        lastSeen: agg.lastSeen,
        relatedEmailIds: Array.from(agg.emailIds).slice(0, RELATED_EMAILS_PER_IP_CAP),
        relatedEmailCount: agg.emailIds.size,
        receivedHopHostnames: Array.from(agg.hostnames),
        reverseDns: reverseDnsByIp.has(ip) ? reverseDnsByIp.get(ip) : null,
        geolocation: geo
          ? {
              country: geo.country,
              region: geo.region,
              city: geo.city,
              latitude: geo.latitude,
              longitude: geo.longitude,
              asn: geo.asn,
              isp: geo.isp,
              provider: geo.provider,
              updatedAt: geo.updatedAt,
            }
          : null,
      };
    });

    await logAuditEvent({
      action: 'NETWORK_INTELLIGENCE_VIEWED',
      resource: 'Organization',
      resourceId: organizationId,
      organizationId,
      actorId: request.user?.sub,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(200).send({
      items,
      truncated: relayHops.length >= RELAY_HOP_CAP,
      // Honest, explicit reason when geolocation enrichment simply never
      // ran for any observed IP — never silently indistinguishable from
      // "no public IPs were ever observed".
      geoEnrichmentAvailable: geoRows.length > 0,
      // Only a boolean (never the actual credential) — lets the frontend
      // distinguish "MaxMind isn't configured in this deployment" from
      // "configured, but nothing has been enriched yet" instead of
      // guessing at a reason.
      maxmindConfigured: Boolean(env.MAXMIND_ACCOUNT_ID && env.MAXMIND_LICENSE_KEY),
    });
  });

  /**
   * Org-wide Indicators of Compromise. Reuses the same aggregation as
   * GET /:emailId/threat-indicators (email.routes.ts) — the underlying
   * data is the same Indicator/ThreatIntelObservation tables, matched
   * against IOC-bearing values already persisted for this organization's
   * emails (aggregateOrgIndicators), never a second indicator model.
   */
  server.get('/indicators', {
    schema: { querystring: fastifyIndicatorListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('EMAIL_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as {
      page: number;
      limit: number;
      q?: string;
      type?: string;
      severity?: string;
      source?: string;
      status?: string;
    };

    const { indicators: aggregated, truncated } = await aggregateOrgIndicators(organizationId);

    const allValues = Array.from(new Set(aggregated.map((i) => i.value)));
    const allEmailIds = Array.from(new Set(aggregated.flatMap((i) => Array.from(i.emailIds))));

    const [observationRows, emailRows] = await Promise.all([
      allValues.length > 0
        ? prisma.indicator.findMany({
            where: { value: { in: allValues } },
            include: { observations: { orderBy: { observationTime: 'desc' }, take: 5 } },
          })
        : Promise.resolve([]),
      allEmailIds.length > 0
        ? prisma.email.findMany({
            where: { id: { in: allEmailIds }, organizationId },
            select: { id: true, caseId: true },
          })
        : Promise.resolve([]),
    ]);

    const indicatorByValue = new Map(observationRows.map((row) => [row.value, row]));
    const caseIdByEmailId = new Map(emailRows.map((row) => [row.id, row.caseId]));

    let items = aggregated.map((agg) => {
      const indicatorRow = indicatorByValue.get(agg.value);
      const latestObservation = indicatorRow?.observations[0] ?? null;
      const relatedCaseIds = new Set(
        Array.from(agg.emailIds)
          .map((emailId) => caseIdByEmailId.get(emailId))
          .filter((caseId): caseId is string => Boolean(caseId))
      );

      return {
        type: agg.type,
        value: agg.value,
        source: latestObservation?.provider ?? null,
        severity: severityFromVerdict(latestObservation?.verdict),
        confidence: latestObservation?.confidence ?? null,
        reputation: latestObservation?.verdict ?? 'UNKNOWN',
        firstSeen: agg.firstSeen,
        lastSeen: agg.lastSeen,
        relatedEmailCount: agg.emailIds.size,
        relatedCaseCount: relatedCaseIds.size,
        relatedEmailIds: Array.from(agg.emailIds).slice(0, 5),
        extractionSources: Array.from(agg.extractionSources),
        cti: indicatorRow
          ? {
              indicatorId: indicatorRow.id,
              observations: indicatorRow.observations.map((o) => ({
                id: o.id,
                provider: o.provider,
                verdict: o.verdict,
                confidence: o.confidence,
                observationTime: o.observationTime,
              })),
            }
          : null,
        createdAt: agg.firstSeen,
      };
    });

    if (query.type) items = items.filter((i) => i.type === query.type);
    if (query.severity) items = items.filter((i) => i.severity === query.severity);
    if (query.status) items = items.filter((i) => i.reputation === query.status);
    if (query.source) items = items.filter((i) => (i.source ?? '').toLowerCase() === query.source!.toLowerCase());
    if (query.q) {
      const needle = query.q.toLowerCase();
      items = items.filter((i) => i.value.toLowerCase().includes(needle));
    }

    // Deterministic ordering: most recently observed first, tie-broken by value.
    items.sort((a, b) => {
      const byDate = b.lastSeen.getTime() - a.lastSeen.getTime();
      if (byDate !== 0) return byDate;
      return a.value.localeCompare(b.value);
    });

    const total = items.length;
    const start = (query.page - 1) * query.limit;
    const pageItems = items.slice(start, start + query.limit);

    await logAuditEvent({
      action: 'INDICATORS_VIEWED',
      resource: 'Organization',
      resourceId: organizationId,
      organizationId,
      actorId: request.user?.sub,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(200).send({
      items: pageItems,
      page: query.page,
      limit: query.limit,
      total,
      totalPages: Math.max(1, Math.ceil(total / query.limit)),
      truncated,
    });
  });
}
