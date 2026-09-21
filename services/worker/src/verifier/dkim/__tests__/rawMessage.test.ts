import { describe, it, expect } from 'vitest';
import { splitRawMessage } from '../rawMessage';

describe('splitRawMessage', () => {
  it('splits headers from body at the first blank line', () => {
    const raw = Buffer.from('From: a@example.com\r\nTo: b@example.com\r\n\r\nHello body\r\n', 'latin1');
    const { headers, body } = splitRawMessage(raw);

    expect(headers).toHaveLength(2);
    expect(headers[0]).toEqual({ name: 'From', value: ' a@example.com', raw: 'From: a@example.com' });
    expect(headers[1]).toEqual({ name: 'To', value: ' b@example.com', raw: 'To: b@example.com' });
    expect(body.toString('latin1')).toBe('Hello body\r\n');
  });

  it('joins folded continuation lines into the preceding header, preserving the fold', () => {
    const raw = Buffer.from('Subject: line one\r\n line two\r\n\r\nBody\r\n', 'latin1');
    const { headers } = splitRawMessage(raw);

    expect(headers).toHaveLength(1);
    expect(headers[0].raw).toBe('Subject: line one\r\n line two');
    expect(headers[0].value).toBe(' line one\r\n line two');
  });

  it('normalizes bare LF line endings to CRLF before splitting', () => {
    const raw = Buffer.from('From: a@example.com\nTo: b@example.com\n\nHello\n', 'latin1');
    const { headers, body } = splitRawMessage(raw);

    expect(headers).toHaveLength(2);
    expect(headers[0].raw).toBe('From: a@example.com');
    expect(body.toString('latin1')).toBe('Hello\r\n');
  });

  it('handles a message with no body separator at all without crashing', () => {
    const raw = Buffer.from('From: a@example.com\r\nTo: b@example.com', 'latin1');
    const { headers, body } = splitRawMessage(raw);

    expect(headers.length).toBeGreaterThan(0);
    expect(body.length).toBe(0);
  });

  it('preserves the exact original byte value of the body (no re-encoding corruption)', () => {
    const bodyBytes = Buffer.from([0x48, 0x65, 0xff, 0x00, 0x9a]); // arbitrary non-UTF8-safe bytes
    const raw = Buffer.concat([Buffer.from('A: b\r\n\r\n', 'latin1'), bodyBytes]);
    const { body } = splitRawMessage(raw);
    expect(body.equals(bodyBytes)).toBe(true);
  });
});
