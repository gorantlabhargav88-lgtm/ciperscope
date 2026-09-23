import { sha256Hex } from './CanonicalHash';

export interface CustodyEventData {
  action: string;
  actorId: string | null;
  description: string | null;
  timestamp: Date;
}

const GENESIS_MARKER = 'GENESIS';

/**
 * SHA256(previousEventHash ?? 'GENESIS' + canonical event fields). The
 * genesis (first) event for a given piece of evidence hashes against the
 * fixed 'GENESIS' marker instead of null/empty, so a genesis event's hash
 * is never confusable with (and never collides with) a non-genesis event
 * whose previous hash happened to be empty/missing.
 */
export function computeEventHash(previousEventHash: string | null, event: CustodyEventData): string {
  const canonical = JSON.stringify({
    previousEventHash: previousEventHash ?? GENESIS_MARKER,
    action: event.action,
    actorId: event.actorId ?? '',
    description: event.description ?? '',
    timestamp: event.timestamp.toISOString(),
  });
  return sha256Hex(canonical);
}

export interface CustodyChainLink {
  id: string;
  eventHash: string | null;
  previousEventId: string | null;
  action: string;
  actorId: string | null;
  description: string | null;
  timestamp: Date;
}

export type CustodyChainVerification =
  | { valid: true }
  | { valid: false; reason: 'EMPTY_CHAIN' | 'MISSING_EVENT_HASH' | 'BROKEN_LINK' | 'HASH_MISMATCH' | 'REORDERED_OR_MISSING_EVENT'; eventId?: string };

/**
 * Verifies a full custody chain for one piece of evidence, walking strictly
 * from genesis (previousEventId === null) forward via each event's
 * `previousEventId` pointer — never by timestamp or array order, so a
 * reordering or deletion attack that leaves timestamps looking plausible
 * still fails verification. Never returns `valid: true` for an incomplete
 * chain (missing hashes, a broken link, or events that don't form a single
 * unbroken sequence covering every row passed in).
 */
export function verifyCustodyChain(events: CustodyChainLink[]): CustodyChainVerification {
  if (events.length === 0) return { valid: false, reason: 'EMPTY_CHAIN' };

  const byId = new Map(events.map((e) => [e.id, e]));
  const byPreviousId = new Map(events.map((e) => [e.previousEventId, e]));

  const genesisCandidates = events.filter((e) => e.previousEventId === null);
  if (genesisCandidates.length !== 1) {
    // Zero genesis events (all reference a previous that isn't in this set
    // — an incomplete chain) or more than one (a forked/tampered chain).
    return { valid: false, reason: 'REORDERED_OR_MISSING_EVENT' };
  }

  let current: CustodyChainLink | undefined = genesisCandidates[0];
  let previousHash: string | null = null;
  const visited = new Set<string>();

  while (current) {
    if (visited.has(current.id)) return { valid: false, reason: 'REORDERED_OR_MISSING_EVENT' }; // cycle
    visited.add(current.id);

    if (!current.eventHash) return { valid: false, reason: 'MISSING_EVENT_HASH', eventId: current.id };

    const expected = computeEventHash(previousHash, {
      action: current.action,
      actorId: current.actorId,
      description: current.description,
      timestamp: current.timestamp,
    });
    if (expected !== current.eventHash) return { valid: false, reason: 'HASH_MISMATCH', eventId: current.id };

    previousHash = current.eventHash;
    current = byPreviousId.get(current.id);
  }

  if (visited.size !== events.length) return { valid: false, reason: 'REORDERED_OR_MISSING_EVENT' };
  // Sanity: every event we visited must exist in byId (always true by
  // construction) — kept as an explicit assertion of the invariant.
  for (const id of visited) if (!byId.has(id)) return { valid: false, reason: 'BROKEN_LINK', eventId: id };

  return { valid: true };
}
