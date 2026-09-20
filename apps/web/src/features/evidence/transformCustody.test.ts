import { describe, it, expect } from 'vitest';
import { buildCustodyChain } from './transformCustody';
import type { ChainOfCustodyEntry } from '@ciperscope/types';

function entry(overrides: Partial<ChainOfCustodyEntry> = {}): ChainOfCustodyEntry {
  return {
    id: 'evt-1',
    action: 'COLLECTED',
    actorId: null,
    actor: null,
    description: null,
    timestamp: '2026-01-01T00:00:00.000Z',
    previousEventId: null,
    ...overrides,
  };
}

describe('buildCustodyChain', () => {
  it('empty custody history returns an empty array', () => {
    expect(buildCustodyChain([])).toEqual([]);
  });

  it('multiple custody entries are all represented', () => {
    const chain = buildCustodyChain([
      entry({ id: 'e1', action: 'COLLECTED' }),
      entry({ id: 'e2', action: 'HASHED', previousEventId: 'e1' }),
      entry({ id: 'e3', action: 'VERIFIED', previousEventId: 'e2' }),
    ]);
    expect(chain).toHaveLength(3);
    expect(chain.map((c) => c.action)).toEqual(['COLLECTED', 'HASHED', 'VERIFIED']);
  });

  it('resolves previousAction from the same fetched list', () => {
    const chain = buildCustodyChain([
      entry({ id: 'e1', action: 'COLLECTED' }),
      entry({ id: 'e2', action: 'HASHED', previousEventId: 'e1' }),
    ]);
    expect(chain[1].previousAction).toBe('COLLECTED');
    expect(chain[0].previousAction).toBeNull();
  });

  it('previousEventId pointing outside the current page yields null, not a guess', () => {
    const chain = buildCustodyChain([entry({ id: 'e2', action: 'HASHED', previousEventId: 'not-in-this-page' })]);
    expect(chain[0].previousAction).toBeNull();
  });

  it('missing custody actor renders "Not available" when there is no actorId at all', () => {
    const chain = buildCustodyChain([entry({ actorId: null, actor: null })]);
    expect(chain[0].actorLabel).toBe('Not available');
  });

  it('an actorId present but no resolved actor renders "Unknown actor", not a fabricated name', () => {
    const chain = buildCustodyChain([entry({ actorId: 'user-1', actor: null })]);
    expect(chain[0].actorLabel).toBe('Unknown actor');
  });

  it('a resolved actor prefers full name, falling back to email', () => {
    const withName = buildCustodyChain([
      entry({ actorId: 'u1', actor: { id: 'u1', email: 'a@b.com', firstName: 'Jane', lastName: 'Doe' } }),
    ]);
    expect(withName[0].actorLabel).toBe('Jane Doe');

    const emailOnly = buildCustodyChain([
      entry({ actorId: 'u1', actor: { id: 'u1', email: 'a@b.com', firstName: null, lastName: null } }),
    ]);
    expect(emailOnly[0].actorLabel).toBe('a@b.com');
  });

  it('missing/invalid entries (no id or no action) are dropped, not rendered broken', () => {
    const chain = buildCustodyChain([
      entry({ id: 'e1' }),
      { ...entry({ id: '' }) },
      { ...entry(), id: 'e2', action: '' as ChainOfCustodyEntry['action'] },
    ]);
    expect(chain).toHaveLength(1);
    expect(chain[0].id).toBe('e1');
  });

  it('a missing hash is not this function\'s concern (evidence-level, not custody-level) and does not throw', () => {
    expect(() => buildCustodyChain([entry()])).not.toThrow();
  });
});
