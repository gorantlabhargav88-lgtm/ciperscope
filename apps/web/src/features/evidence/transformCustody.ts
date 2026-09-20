import type { ChainOfCustodyEntry } from '@ciperscope/types';

export interface CustodyChainNode {
  id: string;
  action: string;
  actorLabel: string;
  description: string | null;
  timestamp: string | null;
  /** The action of the entry this one's previousEventId points to, resolved from the same fetched list. Null if unknown/first event. */
  previousAction: string | null;
}

function actorLabel(entry: ChainOfCustodyEntry): string {
  if (!entry.actor) return entry.actorId ? 'Unknown actor' : 'Not available';
  const name = [entry.actor.firstName, entry.actor.lastName].filter(Boolean).join(' ');
  return name || entry.actor.email;
}

/**
 * Builds a display-ready custody chain from the raw
 * GET /cases/:caseId/evidence/:evidenceId/custody response.
 *
 * Resolves each entry's "previous state" by looking up `previousEventId`
 * within the SAME fetched list (the backend does not resolve this itself —
 * see ChainOfCustodyEntry's doc comment). If the previous event isn't in
 * the current page of results, "previousAction" is null — never guessed.
 *
 * Malformed entries (missing id or action) are dropped rather than
 * rendered as broken rows. Never fabricates an actor, hash, or timestamp.
 */
export function buildCustodyChain(entries: ChainOfCustodyEntry[]): CustodyChainNode[] {
  const byId = new Map(entries.filter((e) => e && e.id).map((e) => [e.id, e]));

  return entries
    .filter((e): e is ChainOfCustodyEntry => Boolean(e && e.id && e.action))
    .map((entry) => {
      const previous = entry.previousEventId ? byId.get(entry.previousEventId) : undefined;
      return {
        id: entry.id,
        action: entry.action,
        actorLabel: actorLabel(entry),
        description: entry.description,
        timestamp: entry.timestamp ?? null,
        previousAction: previous?.action ?? null,
      };
    });
}
