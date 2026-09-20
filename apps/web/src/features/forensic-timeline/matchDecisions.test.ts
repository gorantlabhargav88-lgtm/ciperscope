import { describe, it, expect } from 'vitest';
import { buildDecisionIndex, findDecisionForTarget } from './matchDecisions';
import type { AnalystDecision } from '@ciperscope/types';

function decision(overrides: Partial<AnalystDecision> = {}): AnalystDecision {
  return {
    id: 'd1',
    targetId: 'target-1',
    targetType: 'Indicator',
    decision: 'REVIEWED',
    reason: undefined,
    actorId: 'user-1',
    createdAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

describe('buildDecisionIndex / findDecisionForTarget', () => {
  it('empty decision history: no target resolves to a decision', () => {
    const index = buildDecisionIndex([[]]);
    expect(findDecisionForTarget(index, 'target-1')).toBeNull();
  });

  it('a single decision is found by its targetId', () => {
    const index = buildDecisionIndex([[decision({ targetId: 't1', decision: 'CONFIRMED' })]]);
    expect(findDecisionForTarget(index, 't1')?.decision).toBe('CONFIRMED');
  });

  it('when multiple decisions target the same id, the most recent by createdAt wins', () => {
    const index = buildDecisionIndex([
      [
        decision({ targetId: 't1', decision: 'REVIEWED', createdAt: '2026-01-01T00:00:00.000Z' }),
        decision({ targetId: 't1', decision: 'CONFIRMED', createdAt: '2026-01-02T00:00:00.000Z' }),
      ],
    ]);
    expect(findDecisionForTarget(index, 't1')?.decision).toBe('CONFIRMED');
  });

  it('merges decisions across multiple investigations (multiple lists) without losing any target', () => {
    const index = buildDecisionIndex([[decision({ targetId: 't1' })], [decision({ targetId: 't2' })]]);
    expect(findDecisionForTarget(index, 't1')).not.toBeNull();
    expect(findDecisionForTarget(index, 't2')).not.toBeNull();
  });

  it('a malformed decision entry (missing targetId) is skipped rather than throwing', () => {
    expect(() => buildDecisionIndex([[{ ...decision(), targetId: '' }, decision({ targetId: 't1' })]])).not.toThrow();
    const index = buildDecisionIndex([[{ ...decision(), targetId: '' }, decision({ targetId: 't1' })]]);
    expect(findDecisionForTarget(index, 't1')).not.toBeNull();
  });

  it('a target never given a decision returns null, never inferred from severity/priority', () => {
    const index = buildDecisionIndex([[decision({ targetId: 't1' })]]);
    expect(findDecisionForTarget(index, 'never-decided')).toBeNull();
  });

  it('P1/P2/P3 priority is never used to auto-populate a decision: a high-priority target with zero real decisions still returns null, not a fabricated CONFIRMED', () => {
    // buildDecisionIndex takes only real AnalystDecision rows as input — there
    // is no priority parameter it could even read, by construction. This
    // test documents that invariant explicitly rather than trusting it silently.
    const index = buildDecisionIndex([[]]);
    expect(findDecisionForTarget(index, 'p1-target-with-no-human-decision-yet')).toBeNull();
  });
});
