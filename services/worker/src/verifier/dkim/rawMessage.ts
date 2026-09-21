/**
 * Splits a raw RFC 5322 message into its header lines and body, preserving
 * the exact original bytes needed for DKIM canonicalization (RFC 6376 §3.4).
 * This deliberately does NOT use mailparser: mailparser decodes/normalizes
 * header and body content, which is unusable for DKIM — canonicalization
 * must operate on the message exactly as it was signed.
 */

export interface RawHeader {
  /** Header field name exactly as it appears before the first ':'. */
  name: string;
  /** Everything after the first ':', including any original line folding, without this header's own trailing CRLF. */
  value: string;
  /** The complete original "name:value" text (with folding), without a trailing CRLF. Used by "simple" canonicalization. */
  raw: string;
}

export interface RawMessage {
  headers: RawHeader[];
  body: Buffer;
}

/**
 * Normalizes line endings to CRLF (bare LF -> CRLF, existing CRLF left
 * alone). Real messages are signed assuming CRLF line endings; storage or
 * transport paths that normalize to LF-only would otherwise make every
 * signature fail canonicalization for a reason unrelated to authenticity.
 * This only ever affects line-terminator bytes, never header/body content,
 * so it cannot be used to bypass a genuine content modification.
 */
function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\n/g, '\r\n');
}

export function splitRawMessage(input: Buffer): RawMessage {
  // latin1 maps each byte to one char 1:1, so re-encoding back to a Buffer
  // with 'latin1' reproduces the exact original bytes for any byte value.
  const text = normalizeLineEndings(input.toString('latin1'));

  const boundaryIndex = text.indexOf('\r\n\r\n');
  const headerBlock = boundaryIndex === -1 ? text : text.slice(0, boundaryIndex);
  const bodyText = boundaryIndex === -1 ? '' : text.slice(boundaryIndex + 4);

  const headers: RawHeader[] = [];
  if (headerBlock.length > 0) {
    const lines = headerBlock.split('\r\n');
    for (const line of lines) {
      if (/^[ \t]/.test(line)) {
        // Folded continuation of the previous header field.
        const prev = headers[headers.length - 1];
        if (!prev) continue; // malformed leading fold with no preceding header; ignore defensively
        prev.value += '\r\n' + line;
        prev.raw += '\r\n' + line;
        continue;
      }
      const colonIndex = line.indexOf(':');
      if (colonIndex === -1) continue; // malformed header line without a colon; ignore defensively
      headers.push({
        name: line.slice(0, colonIndex),
        value: line.slice(colonIndex + 1),
        raw: line
      });
    }
  }

  return { headers, body: Buffer.from(bodyText, 'latin1') };
}
