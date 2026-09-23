import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { computeEvidenceHash } from '@ciperscope/integrity';
import { fastifyEvidenceListQuerySchema, fastifyGlobalEvidenceParamsSchema } from '../../utils/validation';
import { logAuditEvent } from '../../utils/audit';
import { verifyEvidenceIntegrity } from './integrityVerification';

// storageKey is the raw backend storage path/key for the evidence file — treated as
// sensitive and never returned to API clients, matching the established convention
// for the analogous Email.rawStorageKey field (see services/api/src/modules/case/case.routes.ts).
const EVIDENCE_SAFE_SELECT = {
  id: true,
  caseId: true,
  type: true,
  filename: true,
  mimeType: true,
  sizeBytes: true,
  sha256: true,
  status: true,
  collectionTime: true,
  collectedById: true,
  sourceSystem: true
} as const;

export default async function evidenceRoutes(server: FastifyInstance) {
  server.get('/', {
    schema: { querystring: fastifyEvidenceListQuerySchema },
    preValidation: [server.authenticate, server.requirePermission('EVIDENCE_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const query = request.query as any;
    const limit = query.limit;

    let cursorOpt: any = undefined;
    if (query.cursor) {
      try {
        const decodedString = Buffer.from(query.cursor, 'base64').toString('utf-8');
        const decoded = JSON.parse(decodedString);
        cursorOpt = { id: decoded[1] };
      } catch (err) {
        return reply.status(400).send({ error: 'Bad Request', message: 'Malformed cursor' });
      }
    }

    try {
      const items = await prisma.evidence.findMany({
        where: { organizationId },
        select: EVIDENCE_SAFE_SELECT,
        take: limit + 1,
        skip: cursorOpt ? 1 : 0,
        cursor: cursorOpt,
        orderBy: [
          { collectionTime: 'desc' },
          { id: 'desc' }
        ],
      });

      let nextCursor: string | null = null;
      if (items.length > limit) {
        items.pop();
        const lastItem = items[items.length - 1];
        if (lastItem) {
          nextCursor = Buffer.from(JSON.stringify([lastItem.collectionTime.toISOString(), lastItem.id])).toString('base64');
        }
      }

      return reply.status(200).send({ items, nextCursor });
    } catch (err: any) {
      if (err.code === 'P2025') {
        return reply.status(400).send({ error: 'Bad Request', message: 'Invalid cursor: record not found or inaccessible' });
      }
      throw err;
    }
  });

  server.get('/:evidenceId', {
    schema: { params: fastifyGlobalEvidenceParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('EVIDENCE_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { evidenceId } = request.params as { evidenceId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const evidence = await prisma.evidence.findFirst({
      where: { id: evidenceId, organizationId },
      select: EVIDENCE_SAFE_SELECT,
    });

    if (!evidence) {
      return reply.status(404).send({ error: 'Not Found', message: 'Evidence not found' });
    }

    await logAuditEvent({
      action: 'EVIDENCE_VIEWED',
      resource: 'Evidence',
      resourceId: evidence.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      req: request,
    });

    return reply.status(200).send(evidence);
  });

  // Phase M — integrity verification. Never returns storageKey, evidence
  // content, or any blockchain credential; only hashes/status/references.
  server.get('/:evidenceId/integrity', {
    schema: { params: fastifyGlobalEvidenceParamsSchema },
    preValidation: [server.authenticate, server.requirePermission('EVIDENCE_READ')]
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { evidenceId } = request.params as { evidenceId: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const evidence = await prisma.evidence.findFirst({
      where: { id: evidenceId, organizationId },
    });
    if (!evidence) {
      return reply.status(404).send({ error: 'Not Found', message: 'Evidence not found' });
    }

    const custodyEvents = await prisma.chainOfCustodyEvent.findMany({ where: { evidenceId } });

    let anchorInput: Parameters<typeof verifyEvidenceIntegrity>[0]['anchor'] = null;
    let batchEvidenceHashes: string[] | null = null;

    if (evidence.anchorId) {
      // organizationId is re-checked here too (not just trusted from the
      // Evidence row) — an anchor can never legitimately belong to a
      // different organization than the evidence pointing at it, but this
      // makes that invariant an explicit query condition, not an assumption.
      const anchor = await prisma.blockchainAnchor.findFirst({
        where: { id: evidence.anchorId, organizationId },
      });
      if (anchor) {
        const batchEvidenceIds = Array.isArray(anchor.evidenceIds) ? (anchor.evidenceIds as string[]) : [];
        const batchEvidenceRows = await prisma.evidence.findMany({
          where: { id: { in: batchEvidenceIds }, organizationId },
        });
        const byId = new Map(batchEvidenceRows.map((e) => [e.id, e]));
        // Recompute in the exact order the batch was built in — a missing
        // row (shouldn't happen, but never assumed) is treated as a real
        // reconstruction failure rather than silently skipped.
        batchEvidenceHashes = batchEvidenceIds.map((id) => {
          const row = byId.get(id);
          if (!row) return ''; // guaranteed to never match a real hash, safely fails Merkle comparison
          return computeEvidenceHash({
            id: row.id, organizationId: row.organizationId, caseId: row.caseId, type: row.type,
            sha256: row.sha256, filename: row.filename, mimeType: row.mimeType, sizeBytes: row.sizeBytes,
            collectionTime: row.collectionTime,
          });
        });
        anchorInput = {
          status: anchor.status,
          merkleRoot: anchor.merkleRoot,
          evidenceCount: anchor.evidenceCount,
          network: anchor.network,
          transactionId: anchor.transactionId,
          blockNumber: anchor.blockNumber,
          anchoredAt: anchor.anchoredAt,
        };
      }
    }

    const result = verifyEvidenceIntegrity({
      evidence: {
        id: evidence.id, organizationId: evidence.organizationId, caseId: evidence.caseId, type: evidence.type,
        sha256: evidence.sha256, filename: evidence.filename, mimeType: evidence.mimeType, sizeBytes: evidence.sizeBytes,
        collectionTime: evidence.collectionTime,
      },
      custodyEvents: custodyEvents.map((c) => ({
        id: c.id, eventHash: c.eventHash, previousEventId: c.previousEventId,
        action: c.action, actorId: c.actorId, description: c.description, timestamp: c.timestamp,
      })),
      anchor: anchorInput,
      batchEvidenceHashes,
    });

    await logAuditEvent({
      action: 'EVIDENCE_INTEGRITY_VERIFIED',
      resource: 'Evidence',
      resourceId: evidence.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      metadata: { integrityStatus: result.status },
      req: request,
    });

    return reply.status(200).send(result);
  });
}
