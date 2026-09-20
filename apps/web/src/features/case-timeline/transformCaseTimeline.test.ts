import { describe, it, expect } from 'vitest';
import { prepareCaseTimeline, describeTimelineAction } from './transformCaseTimeline';
import type { CaseTimelineEvent } from '@ciperscope/types';

function event(overrides: Partial<CaseTimelineEvent> = {}): CaseTimelineEvent {
  return {
    id: 'a1',
    action: 'CASE_CREATED',
    actorId: 'user-1',
    createdAt: '2026-01-01T00:00:00.000Z',
    metadata: null,
    ...overrides,
  };
}

describe('describeTimelineAction', () => {
  it('maps known action codes to readable labels', () => {
    expect(describeTimelineAction('CASE_CREATED')).toBe('Case created');
    expect(describeTimelineAction('CASE_INVESTIGATION_DECISION_RECORDED')).toBe('Analyst decision recorded');
  });

  it('falls back to the raw code for an unknown action rather than inventing a label', () => {
    expect(describeTimelineAction('SOME_FUTURE_ACTION')).toBe('SOME_FUTURE_ACTION');
  });
});

describe('prepareCaseTimeline', () => {
  it('empty timeline returns an empty array', () => {
    expect(prepareCaseTimeline([])).toEqual([]);
  });

  it('sorts events chronologically, newest first', () => {
    const result = prepareCaseTimeline([
      event({ id: 'a1', createdAt: '2026-01-01T00:00:00.000Z' }),
      event({ id: 'a2', createdAt: '2026-01-03T00:00:00.000Z' }),
      event({ id: 'a3', createdAt: '2026-01-02T00:00:00.000Z' }),
    ]);
    expect(result.map((e) => e.id)).toEqual(['a2', 'a3', 'a1']);
  });

  it('de-duplicates events with the same id, keeping the first occurrence', () => {
    const result = prepareCaseTimeline([
      event({ id: 'a1', action: 'CASE_CREATED' }),
      event({ id: 'a1', action: 'CASE_UPDATED' }),
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe('Case created');
  });

  it('an event with a missing timestamp is sorted last, never defaulted to "now"', () => {
    const result = prepareCaseTimeline([
      event({ id: 'a1', createdAt: undefined as unknown as string }),
      event({ id: 'a2', createdAt: '2026-01-01T00:00:00.000Z' }),
    ]);
    expect(result.map((e) => e.id)).toEqual(['a2', 'a1']);
    expect(result[1].timestamp).toBeNull();
  });

  it('an invalid (unparsable) timestamp is treated as unknown, not thrown', () => {
    const result = prepareCaseTimeline([event({ createdAt: 'not-a-date' })]);
    expect(result[0].timestamp).toBeNull();
  });

  it('a malformed event (no id, or no action) is dropped rather than rendered broken', () => {
    const result = prepareCaseTimeline([
      { ...event(), id: '' },
      { ...event(), action: '' },
      event({ id: 'valid' }),
    ]);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('valid');
  });

  it('does not throw on a completely malformed array entry', () => {
    expect(() => prepareCaseTimeline([null as unknown as CaseTimelineEvent, event()])).not.toThrow();
  });
});
