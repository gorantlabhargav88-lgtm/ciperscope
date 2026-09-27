import { FastifyInstance } from 'fastify';
import { prisma } from '@ciperscope/database';
import { env } from '@ciperscope/config';
import { computeEvidenceHash, buildMerkleRoot } from '@ciperscope/integrity';
import { BlockchainProviderConfig } from '@ciperscope/providers';
import { QueueManager } from '@ciperscope/queue';
import { logAuditEvent } from '../../utils/audit';

const queueManager = new QueueManager(env.REDIS_URL || 'redis://127.0.0.1:6379');

export default async function blockchainRoutes(server: FastifyInstance) {
  server.addHook('onClose', async () => {
    await queueManager.closeAll();
  });

  // GET /api/v1/blockchain/anchors - List anchors for the current organization
  server.get('/anchors', {
    preValidation: [server.authenticate, server.requirePermission('EVIDENCE_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const { limit = '50', cursor } = request.query as { limit?: string; cursor?: string };
    const take = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 100);

    const anchors = await prisma.blockchainAnchor.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      take: take + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      select: {
        id: true,
        organizationId: true,
        batchKey: true,
        merkleRoot: true,
        evidenceCount: true,
        hashAlgorithm: true,
        status: true,
        network: true,
        transactionId: true,
        blockNumber: true,
        errorDetails: true,
        anchoredAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    const hasMore = anchors.length > take;
    const items = hasMore ? anchors.slice(0, take) : anchors;
    const nextCursor = hasMore ? items[items.length - 1]?.id : null;

    return reply.status(200).send({
      items,
      nextCursor,
      contractAddress: env.BLOCKCHAIN_CONTRACT_ADDRESS || null,
      network: env.BLOCKCHAIN_NETWORK || 'sepolia',
      blockchainEnabled: env.BLOCKCHAIN_ENABLED === 'true',
    });
  });

  // GET /api/v1/blockchain/anchors/:id - Get anchor details
  server.get('/anchors/:id', {
    preValidation: [server.authenticate, server.requirePermission('EVIDENCE_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { id } = request.params as { id: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const anchor = await prisma.blockchainAnchor.findFirst({
      where: { id, organizationId },
      include: {
        evidence: {
          select: {
            id: true,
            type: true,
            sha256: true,
            filename: true,
            mimeType: true,
            sizeBytes: true,
            collectionTime: true,
            status: true,
          },
        },
      },
    });

    if (!anchor) {
      return reply.status(404).send({ error: 'Not Found', message: 'Blockchain anchor not found' });
    }

    return reply.status(200).send({
      ...anchor,
      contractAddress: env.BLOCKCHAIN_CONTRACT_ADDRESS || null,
    });
  });

  // POST /api/v1/blockchain/anchors - Trigger notarization sweep / batch creation
  server.post('/anchors', {
    preValidation: [server.authenticate, server.requirePermission('CASE_MANAGE_EVIDENCE')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const unbatchedCount = await prisma.evidence.count({
      where: { organizationId, status: 'ACTIVE', anchorId: null },
    });

    const pendingAnchorsCount = await prisma.blockchainAnchor.count({
      where: { organizationId, status: { in: ['BATCHED', 'FAILED'] } },
    });

    // Enqueue worker sweep for immediate execution
    const queue = queueManager.getQueue('evidence-notarization');
    await queue.add('evidence-notarization-on-demand', { organizationId });

    await logAuditEvent({
      action: 'BLOCKCHAIN_NOTARIZATION_TRIGGERED',
      resource: 'BlockchainAnchor',
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      metadata: { unbatchedCount, pendingAnchorsCount },
      req: request,
    });

    return reply.status(202).send({
      message: 'Evidence notarization batch triggered',
      unbatchedEvidenceCount: unbatchedCount,
      pendingAnchorsCount,
      enqueued: true,
    });
  });

  // POST /api/v1/blockchain/anchors/:id/verify - Verify anchor against blockchain
  server.post('/anchors/:id/verify', {
    preValidation: [server.authenticate, server.requirePermission('EVIDENCE_READ')],
  }, async (request, reply) => {
    const organizationId = request.headers['x-organization-id'] as string;
    const { id } = request.params as { id: string };

    if (!organizationId) {
      return reply.status(403).send({ error: 'Tenant isolation failed', message: 'User lacks organization context' });
    }

    const anchor = await prisma.blockchainAnchor.findFirst({
      where: { id, organizationId },
    });

    if (!anchor) {
      return reply.status(404).send({ error: 'Not Found', message: 'Blockchain anchor not found' });
    }

    // 1. Reconstruct and verify local Merkle root from actual evidence rows
    const batchEvidenceIds = Array.isArray(anchor.evidenceIds) ? (anchor.evidenceIds as string[]) : [];
    const evidenceRows = await prisma.evidence.findMany({
      where: { id: { in: batchEvidenceIds }, organizationId },
    });
    const byId = new Map(evidenceRows.map((e) => [e.id, e]));

    const computedHashes = batchEvidenceIds.map((eId) => {
      const row = byId.get(eId);
      if (!row) return '';
      return computeEvidenceHash({
        id: row.id,
        organizationId: row.organizationId,
        caseId: row.caseId,
        type: row.type,
        sha256: row.sha256,
        filename: row.filename,
        mimeType: row.mimeType,
        sizeBytes: row.sizeBytes,
        collectionTime: row.collectionTime,
      });
    });

    const reconstructedRoot = buildMerkleRoot(computedHashes);
    const localMerkleMatches = reconstructedRoot === anchor.merkleRoot;

    // 2. Perform on-chain verification
    const provider = BlockchainProviderConfig.getProvider();
    const onChainResult = await provider.verifyAnchor({
      batchKey: anchor.batchKey,
      merkleRoot: anchor.merkleRoot,
      transactionId: anchor.transactionId,
    });

    const overallVerified =
      anchor.status === 'ANCHORED' && localMerkleMatches && onChainResult.verified;

    const result = {
      verified: overallVerified,
      transactionHash: anchor.transactionId ?? onChainResult.transactionHash,
      network: anchor.network ?? onChainResult.network,
      contractAddress: onChainResult.contractAddress ?? env.BLOCKCHAIN_CONTRACT_ADDRESS ?? null,
      anchoredMerkleRoot: onChainResult.anchoredMerkleRoot,
      localMerkleRoot: anchor.merkleRoot,
      reconstructedMerkleRoot: reconstructedRoot,
      localMerkleMatches,
      blockNumber: anchor.blockNumber ?? onChainResult.blockNumber,
      anchoredAt: anchor.anchoredAt ?? onChainResult.timestamp,
      anchorStatus: anchor.status,
      evidenceCount: anchor.evidenceCount,
      reason: !localMerkleMatches
        ? 'Reconstructed Merkle root does not match stored anchor root'
        : onChainResult.reason ?? (overallVerified ? 'Anchor verified on blockchain' : 'Anchor is not verified on-chain'),
      verifiedAt: new Date().toISOString(),
    };

    await logAuditEvent({
      action: 'BLOCKCHAIN_ANCHOR_VERIFIED',
      resource: 'BlockchainAnchor',
      resourceId: anchor.id,
      actorId: request.user?.sub,
      organizationId,
      status: 'SUCCESS',
      metadata: { verified: overallVerified, status: anchor.status },
      req: request,
    });

    return reply.status(200).send(result);
  });
}
