import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { logAuditEvent } from '../../utils/audit';
import { fastifyUpdateOrgSettingsBodySchema } from '../../utils/validation';

// Keys stored in the existing (previously unused) SystemSetting table —
// see packages/database/prisma/schema.prisma. SystemSetting.value is a
// plain String column, so every preference here is serialized to/from a
// string; there is no dedicated typed settings model, and this reuses the
// real, already-migrated one rather than inventing a new table.
const SETTING_KEYS = {
  notifyOnCriticalCase: 'notifyOnCriticalCase',
  notifyOnThreatDetected: 'notifyOnThreatDetected',
  autoCaseRiskThreshold: 'autoCaseRiskThreshold',
  evidenceRetentionDays: 'evidenceRetentionDays',
} as const;

// Honest, documented defaults used only when no row has ever been saved —
// never presented as "already configured", only as the deployment default.
const DEFAULTS = {
  notifyOnCriticalCase: true,
  notifyOnThreatDetected: true,
  autoCaseRiskThreshold: 'NEVER' as const,
  evidenceRetentionDays: 365,
};

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value === 'true';
}

export default async function settingsRoutes(server: FastifyInstance) {
  server.get('/', {
    preValidation: [server.authenticate, server.requirePermission('USER_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const [organization, settingRows] = await Promise.all([
      prisma.organization.findUnique({ where: { id: organizationId }, select: { id: true, name: true, domain: true, createdAt: true } }),
      prisma.systemSetting.findMany({ where: { organizationId, key: { in: Object.values(SETTING_KEYS) } } }),
    ]);

    if (!organization) {
      return reply.status(404).send({ error: 'Not Found', message: 'Organization not found' });
    }

    const byKey = new Map(settingRows.map((s) => [s.key, s.value]));

    await logAuditEvent({
      action: 'ORG_SETTINGS_VIEWED', resource: 'Organization', resourceId: organizationId,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
    });

    return reply.status(200).send({
      organization,
      preferences: {
        notifyOnCriticalCase: parseBoolean(byKey.get(SETTING_KEYS.notifyOnCriticalCase), DEFAULTS.notifyOnCriticalCase),
        notifyOnThreatDetected: parseBoolean(byKey.get(SETTING_KEYS.notifyOnThreatDetected), DEFAULTS.notifyOnThreatDetected),
        autoCaseRiskThreshold: byKey.get(SETTING_KEYS.autoCaseRiskThreshold) ?? DEFAULTS.autoCaseRiskThreshold,
        evidenceRetentionDays: Number(byKey.get(SETTING_KEYS.evidenceRetentionDays) ?? DEFAULTS.evidenceRetentionDays),
      },
    });
  });

  server.patch('/', {
    schema: { body: fastifyUpdateOrgSettingsBodySchema },
    preValidation: [server.authenticate, server.requirePermission('USER_MANAGE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const body = request.body as {
      displayName?: string;
      notifyOnCriticalCase?: boolean;
      notifyOnThreatDetected?: boolean;
      autoCaseRiskThreshold?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NEVER';
      evidenceRetentionDays?: number;
    };

    // zod-to-json-schema cannot translate a `.refine()` into the AJV/JSON
    // Schema Fastify validates against (the compiled schema only encodes
    // the individual optional properties), so "at least one field" needs
    // an explicit runtime check here rather than relying on the schema
    // alone to reject an empty `{}` body.
    if (Object.keys(body).length === 0) {
      return reply.status(400).send({ error: 'Bad Request', message: 'At least one setting must be provided' });
    }

    const organization = await prisma.organization.findUnique({ where: { id: organizationId } });
    if (!organization) {
      return reply.status(404).send({ error: 'Not Found', message: 'Organization not found' });
    }

    const changedKeys: string[] = [];

    await prisma.$transaction(async (tx) => {
      if (body.displayName !== undefined) {
        await tx.organization.update({ where: { id: organizationId }, data: { name: body.displayName } });
        changedKeys.push('displayName');
      }

      const upserts: { key: string; value: string }[] = [];
      if (body.notifyOnCriticalCase !== undefined) upserts.push({ key: SETTING_KEYS.notifyOnCriticalCase, value: String(body.notifyOnCriticalCase) });
      if (body.notifyOnThreatDetected !== undefined) upserts.push({ key: SETTING_KEYS.notifyOnThreatDetected, value: String(body.notifyOnThreatDetected) });
      if (body.autoCaseRiskThreshold !== undefined) upserts.push({ key: SETTING_KEYS.autoCaseRiskThreshold, value: body.autoCaseRiskThreshold });
      if (body.evidenceRetentionDays !== undefined) upserts.push({ key: SETTING_KEYS.evidenceRetentionDays, value: String(body.evidenceRetentionDays) });

      for (const { key, value } of upserts) {
        await tx.systemSetting.upsert({
          where: { organizationId_key: { organizationId, key } },
          update: { value },
          create: { organizationId, key, value },
        });
        changedKeys.push(key);
      }
    });

    await logAuditEvent({
      action: 'ORG_SETTINGS_UPDATED', resource: 'Organization', resourceId: organizationId,
      organizationId, actorId: request.user?.sub, status: 'SUCCESS', req: request,
      metadata: { changedKeys },
    });

    const [updatedOrg, settingRows] = await Promise.all([
      prisma.organization.findUnique({ where: { id: organizationId }, select: { id: true, name: true, domain: true, createdAt: true } }),
      prisma.systemSetting.findMany({ where: { organizationId, key: { in: Object.values(SETTING_KEYS) } } }),
    ]);
    const byKey = new Map(settingRows.map((s) => [s.key, s.value]));

    return reply.status(200).send({
      organization: updatedOrg,
      preferences: {
        notifyOnCriticalCase: parseBoolean(byKey.get(SETTING_KEYS.notifyOnCriticalCase), DEFAULTS.notifyOnCriticalCase),
        notifyOnThreatDetected: parseBoolean(byKey.get(SETTING_KEYS.notifyOnThreatDetected), DEFAULTS.notifyOnThreatDetected),
        autoCaseRiskThreshold: byKey.get(SETTING_KEYS.autoCaseRiskThreshold) ?? DEFAULTS.autoCaseRiskThreshold,
        evidenceRetentionDays: Number(byKey.get(SETTING_KEYS.evidenceRetentionDays) ?? DEFAULTS.evidenceRetentionDays),
      },
    });
  });
}
