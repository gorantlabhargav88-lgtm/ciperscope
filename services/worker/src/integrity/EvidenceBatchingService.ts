import { PrismaClient, Prisma, BlockchainAnchor } from '@ciperscope/database';
import { computeEvidenceHash, buildMerkleRoot, sha256Hex } from '@ciperscope/integrity';
import { logger } from '@ciperscope/logger';
import { IBlockchainAnchorProvider } from './providers/IBlockchainAnchorProvider';

const MAX_SERIALIZATION_RETRIES = 3;

function isSerializationConflict(err: unknown): boolean {
  // Postgres SQLSTATE 40001 (serialization_failure) / 40P01 (deadlock) as
  // surfaced by Prisma's raw error code passthrough.
  const code = (err as { code?: string; meta?: { code?: string } })?.code;
  const message = err instanceof Error ? err.message : '';
  return code === 'P2034' || /40001|40P01|could not serialize/i.test(message);
}

/**
 * Selects this organization's not-yet-batched ACTIVE evidence (explicit
 * ORDER BY collectionTime, id — never implicit row order), builds a
 * deterministic Merkle root over their canonical hashes, and persists a
 * BlockchainAnchor batch. Idempotent: the batchKey is derived from
 * organizationId + the ordered evidence hashes, so retrying (or two
 * concurrent workers racing) can never create two anchors for the same
 * logical batch — and claiming evidence into the batch (Evidence.anchorId)
 * happens inside a SERIALIZABLE transaction, so two concurrent runs can
 * never both claim overlapping evidence (one loses with a serialization
 * conflict and retries, safely re-reading a now-disjoint eligible set).
 *
 * Returns null when there is no eligible evidence for this organization —
 * that's a legitimate no-op, not an error.
 */
export async function runNotarizationBatch(
  prisma: PrismaClient,
  organizationId: string,
  provider: IBlockchainAnchorProvider
): Promise<BlockchainAnchor | null> {
  // First: retry the external-anchor step for any batch that already
  // exists but never reached a terminal ANCHORED/NOT_CONFIGURED outcome —
  // never re-selects evidence or recomputes the Merkle root for these.
  const retryable = await prisma.blockchainAnchor.findMany({
    where: { organizationId, status: { in: ['BATCHED', 'FAILED'] } },
    orderBy: { createdAt: 'asc' },
  });
  for (const anchor of retryable) {
    await attemptExternalAnchor(prisma, anchor, provider);
  }

  for (let attempt = 0; attempt < MAX_SERIALIZATION_RETRIES; attempt++) {
    try {
      const anchor = await prisma.$transaction(
        async (tx) => {
          const eligible = await tx.evidence.findMany({
            where: { organizationId, status: 'ACTIVE', anchorId: null },
            orderBy: [{ collectionTime: 'asc' }, { id: 'asc' }],
          });
          if (eligible.length === 0) return null;

          const hashes = eligible.map((e) =>
            computeEvidenceHash({
              id: e.id,
              organizationId: e.organizationId,
              caseId: e.caseId,
              type: e.type,
              sha256: e.sha256,
              filename: e.filename,
              mimeType: e.mimeType,
              sizeBytes: e.sizeBytes,
              collectionTime: e.collectionTime,
            })
          );
          const merkleRoot = buildMerkleRoot(hashes);
          if (!merkleRoot) return null; // unreachable given the length check above, kept explicit
          const batchKey = sha256Hex(`${organizationId}:${hashes.join(',')}`);

          const existing = await tx.blockchainAnchor.findUnique({ where: { batchKey } });
          if (existing) return existing;

          const created = await tx.blockchainAnchor.create({
            data: {
              organizationId,
              batchKey,
              merkleRoot,
              evidenceIds: eligible.map((e) => e.id),
              evidenceCount: eligible.length,
              status: 'BATCHED',
            },
          });

          await tx.evidence.updateMany({
            where: { id: { in: eligible.map((e) => e.id) }, anchorId: null },
            data: { anchorId: created.id },
          });

          return created;
        },
        { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
      );

      if (!anchor) return null;
      if (anchor.status === 'ANCHORED' || anchor.status === 'NOT_CONFIGURED') return anchor; // idempotent replay of an already-finished batch
      return await attemptExternalAnchor(prisma, anchor, provider);
    } catch (err) {
      if (isSerializationConflict(err) && attempt < MAX_SERIALIZATION_RETRIES - 1) {
        logger.warn({ organizationId, attempt }, 'Notarization batch hit a serialization conflict; retrying');
        continue;
      }
      throw err;
    }
  }
  throw new Error(`Notarization batch for org ${organizationId} failed after ${MAX_SERIALIZATION_RETRIES} serialization retries`);
}

/**
 * Attempts the external anchoring step for an already-batched anchor,
 * outside any DB transaction (a network call must never hold a DB
 * transaction open). A failure here never corrupts or unclaims the
 * evidence already linked to this anchor — the batch/Merkle work already
 * happened and is real; only the external confirmation is pending/failed.
 */
async function attemptExternalAnchor(
  prisma: PrismaClient,
  anchor: BlockchainAnchor,
  provider: IBlockchainAnchorProvider
): Promise<BlockchainAnchor> {
  try {
    const outcome = await provider.anchorMerkleRoot({
      merkleRoot: anchor.merkleRoot,
      evidenceCount: anchor.evidenceCount,
      organizationId: anchor.organizationId,
      batchKey: anchor.batchKey,
    });

    if (outcome.status === 'ANCHORED') {
      return prisma.blockchainAnchor.update({
        where: { id: anchor.id },
        data: {
          status: 'ANCHORED',
          network: outcome.network,
          transactionId: outcome.transactionId,
          blockNumber: outcome.blockNumber,
          anchoredAt: outcome.anchoredAt,
          errorDetails: null,
        },
      });
    }
    if (outcome.status === 'NOT_CONFIGURED') {
      return prisma.blockchainAnchor.update({ where: { id: anchor.id }, data: { status: 'NOT_CONFIGURED', errorDetails: null } });
    }
    return prisma.blockchainAnchor.update({ where: { id: anchor.id }, data: { status: 'FAILED', errorDetails: outcome.errorMessage } });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    logger.warn({ anchorId: anchor.id, err: message }, 'External anchoring attempt failed (non-fatal, batch remains intact)');
    return prisma.blockchainAnchor.update({ where: { id: anchor.id }, data: { status: 'FAILED', errorDetails: message } });
  }
}
