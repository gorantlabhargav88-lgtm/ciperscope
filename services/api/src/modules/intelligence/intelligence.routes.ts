import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { classifyIp } from '@ciperscope/http-client';
import { env } from '@ciperscope/config';
import { logAuditEvent } from '../../utils/audit';
import { buildReverseDnsByIp } from '../email/email.routes';

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
}
