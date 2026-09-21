import { describe, it, expect } from 'vitest';
import { selectSignedHeaders } from '../headerSelection';
import { RawHeader } from '../rawMessage';

const h = (name: string, value: string): RawHeader => ({ name, value: ` ${value}`, raw: `${name}: ${value}` });

describe('selectSignedHeaders', () => {
  it('selects each named header in the order listed by h=', () => {
    const headers = [h('From', 'a'), h('To', 'b'), h('Subject', 'c')];
    const selected = selectSignedHeaders(['subject', 'from'], headers);
    expect(selected.map(s => s.value.trim())).toEqual(['c', 'a']);
  });

  it('is case-insensitive when matching header names', () => {
    const headers = [h('From', 'a')];
    expect(selectSignedHeaders(['FROM'], headers).map(s => s.value.trim())).toEqual(['a']);
  });

  it('skips a header name in h= that does not exist in the message', () => {
    const headers = [h('From', 'a')];
    expect(selectSignedHeaders(['from', 'x-nonexistent'], headers).map(s => s.value.trim())).toEqual(['a']);
  });

  it('RFC 6376 §5.4.2: for a repeated header name in h=, selects the physically LAST instance first, then works upward', () => {
    // Three "Received" headers, physically top-to-bottom: r1 (oldest hop), r2, r3 (most recent hop)
    const headers = [h('Received', 'r1'), h('Received', 'r2'), h('Received', 'r3'), h('From', 'a')];
    const selected = selectSignedHeaders(['received', 'received', 'from'], headers);
    // First "received" in h= -> bottom-most unused instance (r3); second -> next one up (r2)
    expect(selected.map(s => s.value.trim())).toEqual(['r3', 'r2', 'a']);
  });

  it('never selects more instances of a header than actually exist', () => {
    const headers = [h('From', 'a')];
    const selected = selectSignedHeaders(['from', 'from', 'from'], headers);
    expect(selected.map(s => s.value.trim())).toEqual(['a']);
  });
});
