import { describe, it, expect } from 'vitest';
import { isActionableEvent, getDecisionTarget } from './actionableEvents';
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

describe('isActionableEvent', () => {
  it('EMAIL, AUTHENTICATION, THREAT_INTELLIGENCE, and ML events are actionable', () => {
    expect(isActionableEvent(evt({ category: 'EMAIL' }))).toBe(true);
    expect(isActionableEvent(evt({ category: 'AUTHENTICATION' }))).toBe(true);
    expect(isActionableEvent(evt({ category: 'THREAT_INTELLIGENCE' }))).toBe(true);
    expect(isActionableEvent(evt({ category: 'ML' }))).toBe(true);
  });

  it('EVIDENCE, INVESTIGATION, ANALYST, and SYSTEM events are NOT actionable (already records of what happened)', () => {
    expect(isActionableEvent(evt({ category: 'EVIDENCE' }))).toBe(false);
    expect(isActionableEvent(evt({ category: 'INVESTIGATION' }))).toBe(false);
    expect(isActionableEvent(evt({ category: 'ANALYST' }))).toBe(false);
    expect(isActionableEvent(evt({ category: 'SYSTEM' }))).toBe(false);
  });

  it('an otherwise-actionable event with no resourceId/resourceType is not actionable', () => {
    expect(isActionableEvent(evt({ category: 'EMAIL', resourceId: '' }))).toBe(false);
    expect(isActionableEvent(evt({ category: 'EMAIL', resourceType: '' as ForensicTimelineEvent['resourceType'] }))).toBe(false);
  });
});

describe('getDecisionTarget', () => {
  it('derives targetId/targetType directly from the event\'s real resourceId/resourceType', () => {
    const target = getDecisionTarget(evt({ resourceId: 'ind-123', resourceType: 'Indicator' }));
    expect(target).toEqual({ targetId: 'ind-123', targetType: 'Indicator' });
  });
});
