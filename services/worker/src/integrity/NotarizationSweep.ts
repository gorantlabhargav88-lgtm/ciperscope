import { PrismaClient } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import { runNotarizationBatch } from './EvidenceBatchingService';
import { BlockchainAnchorConfig } from './BlockchainAnchorConfig';

/**
 * Sweeps every organization that has either (a) ACTIVE evidence not yet in
 * any batch, or (b) an existing batch stuck short of a terminal outcome
 * (BATCHED/FAILED), and runs one notarization pass per organization.
 * Batching is fundamentally cross-evidence (it accumulates multiple items
 * before acting), so — like the existing gmail-watch-renewal repeatable
 * job — this runs as a periodic sweep rather than a per-event trigger.
 * Best-effort: one organization's failure never stops the sweep for the
 * rest, and this never touches the primary email/evidence ingestion path.
 */
export async function runNotarizationSweep(prisma: PrismaClient): Promise<{ organizationsProcessed: number; errors: number }> {
  const provider = BlockchainAnchorConfig.getProvider();

  const [pendingEvidenceOrgs, pendingAnchorOrgs] = await Promise.all([
    prisma.evidence.findMany({ where: { status: 'ACTIVE', anchorId: null }, select: { organizationId: true }, distinct: ['organizationId'] }),
    prisma.blockchainAnchor.findMany({ where: { status: { in: ['BATCHED', 'FAILED'] } }, select: { organizationId: true }, distinct: ['organizationId'] }),
  ]);

  const organizationIds = Array.from(new Set([...pendingEvidenceOrgs, ...pendingAnchorOrgs].map((o) => o.organizationId)));

  let errors = 0;
  for (const organizationId of organizationIds) {
    try {
      const anchor = await runNotarizationBatch(prisma, organizationId, provider);
      if (anchor) {
        logger.info({ organizationId, anchorId: anchor.id, status: anchor.status, evidenceCount: anchor.evidenceCount }, 'Notarization batch processed');
      }
    } catch (err) {
      errors += 1;
      logger.warn({ organizationId, err: err instanceof Error ? err.message : 'Unknown error' }, 'Notarization sweep failed for organization (non-fatal, continuing with other organizations)');
    }
  }

  return { organizationsProcessed: organizationIds.length, errors };
}
