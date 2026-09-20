import { describe, it, expect } from 'vitest';
import { prepareForensicTimeline, filterByCategory } from './prepareForensicTimeline';
import type { ForensicTimelineEvent } from '@ciperscope/types';

function evt(overrides: Partial<ForensicTimelineEvent> = {}): ForensicTimelineEvent {
  return {
    id: 'e1',
    timestamp: '2026-01-01T00:00:00.000Z',
    category: 'EMAIL',
    action: 'EMAIL_INGESTED',
    title: 'Email ingested',
    description: null,
    severity: null,
    priority: null,
    source: 'CiperScope',
    resourceType: 'Email',
    resourceId: 'email-1',
    caseId: 'case-1',
    emailId: 'email-1',
    investigationId: null,
    evidenceId: null,
    actor: null,
    metadata: null,
    ...overrides,
  };
}

describe('prepareForensicTimeline', () => {
  it('empty timeline returns no events and no categories', () => {
    const result = prepareForensicTimeline([]);
    expect(result.events).toEqual([]);
    expect(result.availableCategories).toEqual([]);
  });

  it('a single event is represented correctly', () => {
    const result = prepareForensicTimeline([evt()]);
    expect(result.events).toHaveLength(1);
    expect(result.availableCategories).toEqual(['EMAIL']);
  });

  it('multiple events across categories are all kept, category list reflects only what is present', () => {
    const result = prepareForensicTimeline([
      evt({ id: 'e1', category: 'EMAIL' }),
      evt({ id: 'e2', category: 'ML', action: 'ML_CLASSIFIED' }),
      evt({ id: 'e3', category: 'EVIDENCE', action: 'COLLECTED' }),
    ]);
    expect(result.events).toHaveLength(3);
    expect(result.availableCategories).toEqual(['EMAIL', 'ML', 'EVIDENCE']);
  });

  it('sorts chronologically, oldest first (investigation-story order, not activity-feed order)', () => {
    const result = prepareForensicTimeline([
      evt({ id: 'e2', timestamp: '2026-01-03T00:00:00.000Z' }),
      evt({ id: 'e1', timestamp: '2026-01-01T00:00:00.000Z' }),
      evt({ id: 'e3', timestamp: '2026-01-02T00:00:00.000Z' }),
    ]);
    expect(result.events.map((e) => e.id)).toEqual(['e1', 'e3', 'e2']);
  });

  it('removes duplicate events by id, keeping the first occurrence', () => {
    const result = prepareForensicTimeline([evt({ id: 'e1', action: 'EMAIL_INGESTED' }), evt({ id: 'e1', action: 'OTHER' })]);
    expect(result.events).toHaveLength(1);
    expect(result.events[0].action).toBe('EMAIL_INGESTED');
  });

  it('an event with a missing/null timestamp (e.g. unresolved CTI observationTime) sorts last', () => {
    const result = prepareForensicTimeline([
      evt({ id: 'e1', timestamp: null }),
      evt({ id: 'e2', timestamp: '2026-01-01T00:00:00.000Z' }),
    ]);
    expect(result.events.map((e) => e.id)).toEqual(['e2', 'e1']);
  });

  it('an event with a missing actor does not throw and is kept', () => {
    const result = prepareForensicTimeline([evt({ actor: null })]);
    expect(result.events).toHaveLength(1);
  });

  it('an event with no emailId/investigationId/evidenceId (e.g. a pure case-level event) is kept', () => {
    const result = prepareForensicTimeline([evt({ emailId: null, investigationId: null, evidenceId: null, category: 'SYSTEM', action: 'CASE_CREATED' })]);
    expect(result.events).toHaveLength(1);
  });

  it('drops malformed entries (missing id, category, or action) without throwing', () => {
    const result = prepareForensicTimeline([
      { ...evt(), id: '' },
      { ...evt(), category: '' as ForensicTimelineEvent['category'] },
      { ...evt(), action: '' },
      null as unknown as ForensicTimelineEvent,
      evt({ id: 'valid' }),
    ]);
    expect(result.events).toHaveLength(1);
    expect(result.events[0].id).toBe('valid');
  });

  it('P1/P2/P3 priority passes through untouched when present, and is null when absent (e.g. non-email events)', () => {
    const result = prepareForensicTimeline([
      evt({ id: 'e1', priority: { priority: 'P1', reasons: ['test'] } }),
      evt({ id: 'e2', priority: null, category: 'INVESTIGATION', action: 'INVESTIGATION_CREATED' }),
    ]);
    expect(result.events[0].priority?.priority).toBe('P1');
    expect(result.events[1].priority).toBeNull();
  });
});

describe('filterByCategory', () => {
  const events = [
    evt({ id: 'e1', category: 'EMAIL' }),
    evt({ id: 'e2', category: 'ML' }),
    evt({ id: 'e3', category: 'EMAIL' }),
  ];

  it('ALL returns every event unfiltered', () => {
    expect(filterByCategory(events, 'ALL')).toHaveLength(3);
  });

  it('a specific category returns only matching events', () => {
    expect(filterByCategory(events, 'EMAIL').map((e) => e.id)).toEqual(['e1', 'e3']);
  });

  it('a category with no matching events returns an empty array, not an error', () => {
    expect(filterByCategory(events, 'EVIDENCE')).toEqual([]);
  });
});
