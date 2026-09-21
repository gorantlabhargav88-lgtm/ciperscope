/**
 * DKIM canonicalization algorithms, implemented directly from RFC 6376 §3.4
 * ("simple" §3.4.1/§3.4.3, "relaxed" §3.4.2/§3.4.4). Every rule below is
 * transcribed from the RFC text, not inferred from examples.
 */

import { RawHeader } from './rawMessage';

const CRLF = '\r\n';

/** RFC 6376 §3.4.1: header fields presented exactly as they appear in the message. */
export function canonicalizeHeaderSimple(header: RawHeader): string {
  return header.raw + CRLF;
}

/**
 * RFC 6376 §3.4.2, applied in order:
 * - lowercase the header field name
 * - unfold continuation lines
 * - collapse runs of WSP to a single SP
 * - delete WSP at the end of the value
 * - delete WSP immediately before/after the colon
 */
export function canonicalizeHeaderRelaxed(header: RawHeader): string {
  const name = header.name.trim().toLowerCase();
  const unfolded = header.value.replace(/\r\n(?=[ \t])/g, '');
  const collapsed = unfolded.replace(/[ \t]+/g, ' ').trim();
  return `${name}:${collapsed}${CRLF}`;
}

/**
 * RFC 6376 §3.4.3: ignore all empty trailing lines; if there is no body or
 * no trailing CRLF, a CRLF is added. An all-empty/missing body canonicalizes
 * to a single CRLF (verified against RFC 6376's own SHA-256 example for the
 * "simple" empty body: frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=).
 */
export function canonicalizeBodySimple(body: Buffer): Buffer {
  const text = body.toString('latin1');
  const stripped = text.replace(/(\r\n)+$/, '');
  return Buffer.from(stripped + CRLF, 'latin1');
}

/**
 * RFC 6376 §3.4.4:
 * (a) ignore whitespace at the end of lines; collapse runs of WSP within a
 *     line to a single SP (CRLF line terminators themselves are untouched).
 * (b) ignore all empty lines at the end of the body; if the body is
 *     non-empty but does not end with CRLF, a CRLF is added. Unlike
 *     "simple", a fully empty (or all-blank-lines) body canonicalizes to
 *     the empty string, not a CRLF — verified against RFC 6376's own
 *     SHA-256 example for the "relaxed" empty body:
 *     47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU= (= SHA-256 of "").
 */
export function canonicalizeBodyRelaxed(body: Buffer): Buffer {
  const text = body.toString('latin1');
  const lines = text.split('\r\n').map(line => line.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  let joined = lines.join(CRLF);
  joined = joined.replace(/(\r\n)+$/, '');
  if (joined.length > 0) {
    joined += CRLF;
  }
  return Buffer.from(joined, 'latin1');
}
