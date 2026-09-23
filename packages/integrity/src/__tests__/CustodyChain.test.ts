import { describe, it, expect } from 'vitest';
import { computeEventHash, verifyCustodyChain, CustodyChainLink } from '../CustodyChain';

function buildValidChain(length: number): CustodyChainLink[] {
  const events: CustodyChainLink[] = [];
  let previousId: string | null = null;
  let previousHash: string | null = null;
  for (let i = 0; i < length; i++) {
    const id = `event-${i}`;
    const timestamp = new Date(2026, 0, 1, 0, 0, i);
    const data = { action: i === 0 ? 'COLLECTED' : 'ACCESSED', actorId: 'user-1', description: null, timestamp };
    const eventHash = computeEventHash(previousHash, data);
    events.push({ id, eventHash, previousEventId: previousId, ...data });
    previousId = id;
    previousHash = eventHash;
  }
  return events;
}

describe('verifyCustodyChain', () => {
  it('a valid chain of any length verifies true', () => {
    expect(verifyCustodyChain(buildValidChain(1))).toEqual({ valid: true });
    expect(verifyCustodyChain(buildValidChain(5))).toEqual({ valid: true });
  });

  it('an empty chain is explicitly invalid (EMPTY_CHAIN), never silently valid', () => {
    expect(verifyCustodyChain([])).toEqual({ valid: false, reason: 'EMPTY_CHAIN' });
  });

  it('a tampered event (description changed after the fact) breaks verification', () => {
    const chain = buildValidChain(3);
    chain[1] = { ...chain[1], description: 'tampered' };
    const result = verifyCustodyChain(chain);
    expect(result.valid).toBe(false);
    expect(result).toMatchObject({ reason: 'HASH_MISMATCH', eventId: 'event-1' });
  });

  it('reordered events (swapping two non-adjacent-in-time events\' linkage) break verification', () => {
    const chain = buildValidChain(3);
    // Swap event-1 and event-2's previousEventId pointers — this both
    // breaks the linear chain (no valid single path) and, even if it
    // didn't, would produce a hash mismatch.
    const swapped = [chain[0], { ...chain[2], previousEventId: chain[0].id }, { ...chain[1], previousEventId: chain[2].id }];
    const result = verifyCustodyChain(swapped);
    expect(result.valid).toBe(false);
  });

  it('a missing event (gap in the chain) is detected, not silently accepted as a shorter valid chain', () => {
    const chain = buildValidChain(4);
    const withGap = [chain[0], chain[1], chain[3]]; // event-2 removed; event-3's previousEventId still points to it
    const result = verifyCustodyChain(withGap);
    expect(result.valid).toBe(false);
    expect(result).toMatchObject({ reason: 'REORDERED_OR_MISSING_EVENT' });
  });

  it('a broken previousEventHash (event claims a different predecessor hash than actually occurred) fails', () => {
    const chain = buildValidChain(2);
    // Recompute event-1's hash as if genesis's hash were something else.
    const forgedHash = computeEventHash('not-the-real-genesis-hash', {
      action: chain[1].action, actorId: chain[1].actorId, description: chain[1].description, timestamp: chain[1].timestamp,
    });
    chain[1] = { ...chain[1], eventHash: forgedHash };
    const result = verifyCustodyChain(chain);
    expect(result).toMatchObject({ valid: false, reason: 'HASH_MISMATCH' });
  });

  it('an event with no stored eventHash (predates the field) is INCOMPLETE, never treated as valid', () => {
    const chain = buildValidChain(2);
    chain[1] = { ...chain[1], eventHash: null };
    expect(verifyCustodyChain(chain)).toEqual({ valid: false, reason: 'MISSING_EVENT_HASH', eventId: 'event-1' });
  });

  it('two independent genesis events (a forked chain) are rejected', () => {
    const a = buildValidChain(1);
    const b = buildValidChain(1);
    b[0] = { ...b[0], id: 'event-b-0' };
    expect(verifyCustodyChain([...a, ...b])).toEqual({ valid: false, reason: 'REORDERED_OR_MISSING_EVENT' });
  });

  it('the same logical chain verifies identically regardless of array input order', () => {
    const chain = buildValidChain(4);
    const shuffled = [chain[2], chain[0], chain[3], chain[1]];
    expect(verifyCustodyChain(chain)).toEqual(verifyCustodyChain(shuffled));
  });
});
