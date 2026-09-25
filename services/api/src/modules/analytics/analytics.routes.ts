import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { logAuditEvent } from '../../utils/audit';
import { fastifyAnalyticsOverviewQuerySchema } from '../../utils/validation';
import { aggregateOrgIndicators } from '../intelligence/indicatorAggregation';

const RANGE_MS: Record<string, number> = {
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
  '90d': 90 * 24 * 60 * 60 * 1000,
};

// Same "read-only, already-persisted, bounded" pattern used throughout —
// enough to bucket activity for the selected range without loading an
// unbounded table into Node.
const EMAIL_TIMELINE_CAP = 10000;
const ATTACHMENT_STAT_CAP = 10000;

// Non-fabricated, deterministic policy: which EmailClassification values
// count as a detected threat for the "Threats Detected" stat/severity
// breakdown. Mirrors the classifications flagged as malicious in
// packages/types/src/threat.ts's calculateThreatPriority.
const THREAT_CLASSIFICATIONS = ['PHISHING', 'IMPERSONATION', 'BEC', 'FRAUD', 'MALWARE', 'SUSPICIOUS'] as const;

function bucketKey(date: Date, range: string): string {
  // Hourly buckets for 24h, daily buckets otherwise — keeps the number of
  // buckets small and readable regardless of range.
  if (range === '24h') {
    return date.toISOString().slice(0, 13) + ':00:00.000Z'; // yyyy-mm-ddThh
  }
  return date.toISOString().slice(0, 10); // yyyy-mm-dd
}

export default async function analyticsRoutes(server: FastifyInstance) {
  server.get('/overview', {
    schema: { querystring: fastifyAnalyticsOverviewQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')], // same reasonable proxy as dashboard.routes.ts
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const { range } = request.query as { range: '24h' | '7d' | '30d' | '90d' };
    const since = new Date(Date.now() - RANGE_MS[range]);

    const [
      emailsAnalyzed,
      threatsDetected,
      severityDistributionRaw,
      casesByStatusRaw,
      casesByPriorityRaw,
      attachmentStatRows,
      timelineEmailRows,
      indicatorAggregation,
    ] = await Promise.all([
      prisma.email.count({ where: { organizationId, createdAt: { gte: since } } }),
      prisma.email.count({
        where: { organizationId, createdAt: { gte: since }, classification: { in: [...THREAT_CLASSIFICATIONS] } },
      }),
      prisma.riskAssessment.groupBy({
        by: ['riskLevel'],
        where: { email: { organizationId }, createdAt: { gte: since } },
        _count: { _all: true },
      }),
      prisma.case.groupBy({
        by: ['status'],
        where: { organizationId },
        _count: { _all: true },
      }),
      prisma.case.groupBy({
        by: ['priority'],
        where: { organizationId, status: { in: ['OPEN', 'INVESTIGATING'] } },
        _count: { _all: true },
      }),
      prisma.emailAttachment.findMany({
        where: { email: { organizationId, createdAt: { gte: since } } },
        select: { isMismatch: true, apkMetadata: true, qrFindings: true },
        take: ATTACHMENT_STAT_CAP,
      }),
      prisma.email.findMany({
        where: { organizationId, createdAt: { gte: since } },
        select: { createdAt: true, classification: true },
        take: EMAIL_TIMELINE_CAP,
        orderBy: { createdAt: 'desc' },
      }),
      aggregateOrgIndicators(organizationId, since),
    ]);

    // --- Attachment-derived stats (bounded fetch, in-memory count — see cap above) ---
    let suspiciousAttachments = 0;
    let apkDetections = 0;
    let qrDetections = 0;
    for (const a of attachmentStatRows) {
      if (a.isMismatch) suspiciousAttachments += 1;
      if (a.apkMetadata !== null) apkDetections += 1;
      if (a.qrFindings !== null) qrDetections += 1;
    }

    // --- Indicator-derived stats (shared aggregation with GET /intelligence/indicators) ---
    const domainCounts = new Map<string, number>();
    const ipCounts = new Map<string, number>();
    let uniqueIpIndicators = 0;
    let uniqueDomainIndicators = 0;
    for (const ind of indicatorAggregation.indicators) {
      if (ind.type === 'IP') {
        uniqueIpIndicators += 1;
        ipCounts.set(ind.value, ind.emailIds.size);
      } else if (ind.type === 'DOMAIN') {
        uniqueDomainIndicators += 1;
        domainCounts.set(ind.value, ind.emailIds.size);
      }
    }

    const allIndicatorValues = indicatorAggregation.indicators.map((i) => i.value);
    const observationRows = allIndicatorValues.length > 0
      ? await prisma.indicator.findMany({
          where: { value: { in: allIndicatorValues } },
          select: { value: true, observations: { orderBy: { observationTime: 'desc' }, take: 1 } },
        })
      : [];
    const latestVerdictByValue = new Map(
      observationRows.map((row) => [row.value, row.observations[0]?.verdict ?? null])
    );

    let maliciousUrls = 0;
    let ctiObservations = 0;
    for (const row of observationRows) {
      ctiObservations += row.observations.length;
    }
    for (const ind of indicatorAggregation.indicators) {
      if (ind.type === 'URL' && latestVerdictByValue.get(ind.value) === 'MALICIOUS') maliciousUrls += 1;
    }

    const indicatorTypeCounts = new Map<string, number>();
    for (const ind of indicatorAggregation.indicators) {
      indicatorTypeCounts.set(ind.type, (indicatorTypeCounts.get(ind.type) ?? 0) + 1);
    }

    const topDomains = Array.from(domainCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([domain, count]) => ({ domain, count }));
    const topIps = Array.from(ipCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([ip, count]) => ({ ip, count }));

    // --- Threat activity over time (bounded fetch, bucketed in-memory) ---
    const buckets = new Map<string, { total: number; threats: number }>();
    for (const row of timelineEmailRows) {
      const key = bucketKey(row.createdAt, range);
      const bucket = buckets.get(key) ?? { total: 0, threats: 0 };
      bucket.total += 1;
      if ((THREAT_CLASSIFICATIONS as readonly string[]).includes(row.classification)) bucket.threats += 1;
      buckets.set(key, bucket);
    }
    const threatActivity = Array.from(buckets.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([bucket, v]) => ({ bucket, total: v.total, threats: v.threats }));

    const severityDistribution = severityDistributionRaw.map((r) => ({ severity: r.riskLevel, count: r._count._all }));
    const criticalThreats = severityDistribution.find((s) => s.severity === 'CRITICAL')?.count ?? 0;
    const casesByStatus = casesByStatusRaw.map((r) => ({ status: r.status, count: r._count._all }));
    const casesByPriority = casesByPriorityRaw.map((r) => ({ priority: r.priority, count: r._count._all }));
    const openCriticalCases = casesByPriority.find((c) => c.priority === 'CRITICAL')?.count ?? 0;
    const indicatorTypeDistribution = Array.from(indicatorTypeCounts.entries()).map(([type, count]) => ({ type, count }));

    await logAuditEvent({
      action: 'ANALYTICS_VIEWED',
      resource: 'Organization',
      resourceId: organizationId,
      organizationId,
      actorId: request.user?.sub,
      status: 'SUCCESS',
      req: request,
      metadata: { range },
    });

    return reply.status(200).send({
      range,
      since: since.toISOString(),
      emailsAnalyzed,
      threatsDetected,
      criticalThreats,
      openCriticalCases,
      maliciousUrls,
      suspiciousAttachments,
      apkDetections,
      qrDetections,
      uniqueIpIndicators,
      uniqueDomainIndicators,
      ctiObservations,
      severityDistribution,
      casesByStatus,
      casesByPriority,
      indicatorTypeDistribution,
      threatActivity,
      topDomains,
      topIps,
      truncated: indicatorAggregation.truncated || timelineEmailRows.length >= EMAIL_TIMELINE_CAP || attachmentStatRows.length >= ATTACHMENT_STAT_CAP,
    });
  });
}
