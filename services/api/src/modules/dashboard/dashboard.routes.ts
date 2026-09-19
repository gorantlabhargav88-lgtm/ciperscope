import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';

export default async function dashboardRoutes(server: FastifyInstance) {
  server.get('/overview', {
    preValidation: [server.authenticate, server.requirePermission('CASE_READ')] // using CASE_READ as a reasonable proxy
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    // Run queries concurrently
    const openStatus = { in: ['OPEN', 'INVESTIGATING'] as Array<'OPEN' | 'INVESTIGATING'> };

    const [
      activeThreatsCount,
      criticalAlertsCount,
      highPriorityCount,
      mediumPriorityCount,
      lowPriorityCount,
      investigationsCount,
      emailsAnalyzedCount,
      indicatorsTrackedCount,
      recentAlerts
    ] = await Promise.all([
      // Active Threats = Cases with status OPEN or INVESTIGATING
      prisma.case.count({
        where: { organizationId, status: openStatus }
      }),

      // Critical Alerts = open Cases with Priority CRITICAL
      prisma.case.count({
        where: { organizationId, priority: 'CRITICAL', status: openStatus }
      }),

      // Open Cases with Priority HIGH
      prisma.case.count({
        where: { organizationId, priority: 'HIGH', status: openStatus }
      }),

      // Open Cases with Priority MEDIUM
      prisma.case.count({
        where: { organizationId, priority: 'MEDIUM', status: openStatus }
      }),

      // Open Cases with Priority LOW
      prisma.case.count({
        where: { organizationId, priority: 'LOW', status: openStatus }
      }),

      // Investigations count
      prisma.investigation.count({
        where: {
          case: { organizationId }
        }
      }),

      // Emails ingested/analyzed for this org
      prisma.email.count({
        where: { organizationId }
      }),

      // Indicators (IOCs) are a global, shared threat-intel table (not tenant-scoped in the schema)
      prisma.indicator.count(),

      // Recent Alerts = Recent Cases (or Alerts if the model is used)
      prisma.case.findMany({
        where: { organizationId },
        orderBy: { createdAt: 'desc' },
        take: 5,
        select: {
          id: true,
          title: true,
          priority: true,
          status: true,
          createdAt: true
        }
      })
    ]);

    return reply.status(200).send({
      activeThreats: activeThreatsCount,
      criticalAlerts: criticalAlertsCount,
      investigations: investigationsCount,
      emailsAnalyzed: emailsAnalyzedCount,
      indicatorsTracked: indicatorsTrackedCount,
      // Open-case counts by Priority, presented in the UI as P1 (CRITICAL) / P2 (HIGH) / P3 (MEDIUM+LOW)
      priorityBreakdown: {
        critical: criticalAlertsCount,
        high: highPriorityCount,
        medium: mediumPriorityCount,
        low: lowPriorityCount
      },
      recentAlerts: recentAlerts.map(r => ({
        id: r.id,
        title: r.title,
        priority: r.priority,
        status: r.status,
        timestamp: r.createdAt
      }))
    });
  });
}
