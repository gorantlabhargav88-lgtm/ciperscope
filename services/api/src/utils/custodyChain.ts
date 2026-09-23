import { Prisma, PrismaClient } from '@ciperscope/database';
import { computeEventHash } from '@ciperscope/integrity';

type TxOrClient = Prisma.TransactionClient | PrismaClient;

/**
 * Appends one ChainOfCustodyEvent, computing its `eventHash` chained from
 * whatever the current chain tip is for this evidence (found via the
 * existing `previousEventId` self-relation — never a second parallel
 * chain). This is now the ONLY way custody events should be created;
 * calling `tx.chainOfCustodyEvent.create()` directly would silently skip
 * the integrity hash.
 */
export async function appendCustodyEvent(
  tx: TxOrClient,
  params: { evidenceId: string; action: string; actorId?: string | null; description?: string | null }
) {
  const tip = await tx.chainOfCustodyEvent.findFirst({
    where: { evidenceId: params.evidenceId, next: null },
  });

  const timestamp = new Date();
  const eventHash = computeEventHash(tip?.eventHash ?? null, {
    action: params.action,
    actorId: params.actorId ?? null,
    description: params.description ?? null,
    timestamp,
  });

  return tx.chainOfCustodyEvent.create({
    data: {
      evidenceId: params.evidenceId,
      action: params.action as Prisma.ChainOfCustodyEventCreateInput['action'],
      actorId: params.actorId ?? null,
      description: params.description ?? null,
      timestamp,
      previousEventId: tip?.id ?? null,
      eventHash,
    },
  });
}
