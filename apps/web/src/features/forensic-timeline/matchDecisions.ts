import type { AnalystDecision } from '@ciperscope/types';

/**
 * Builds a targetId -> most-recent-decision lookup from one or more
 * investigations' real decision histories (GET .../decisions), so the
 * timeline can show "Analyst Decision: ..." per event from a SINGLE
 * batched fetch (one request per investigation in the case, not one per
 * timeline event — see UnifiedForensicTimeline's loading code).
 *
 * When a target has multiple decisions, the most recent (by createdAt)
 * wins — never inferred or fabricated from severity/priority.
 */
export function buildDecisionIndex(decisionLists: AnalystDecision[][]): Map<string, AnalystDecision> {
  const index = new Map<string, AnalystDecision>();

  for (const decisions of decisionLists) {
    for (const decision of decisions) {
      if (!decision || !decision.targetId) continue;
      const existing = index.get(decision.targetId);
      if (!existing) {
        index.set(decision.targetId, decision);
        continue;
      }
      const existingTime = existing.createdAt ? new Date(existing.createdAt).getTime() : 0;
      const candidateTime = decision.createdAt ? new Date(decision.createdAt).getTime() : 0;
      if (candidateTime >= existingTime) index.set(decision.targetId, decision);
    }
  }

  return index;
}

export function findDecisionForTarget(index: Map<string, AnalystDecision>, targetId: string): AnalystDecision | null {
  return index.get(targetId) ?? null;
}
