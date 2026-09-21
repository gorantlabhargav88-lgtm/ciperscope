import { RawHeader } from './rawMessage';

/**
 * Selects which header field instances to include for DKIM verification,
 * per RFC 6376 §5.4.2: "Signers ... MUST sign the physically last instance
 * of that header field in the header block ... MUST sign such header
 * fields in order from the bottom of the header field block to the top."
 * Nonexistent header fields named in h= are simply skipped.
 */
export function selectSignedHeaders(headerNames: string[], allHeaders: RawHeader[]): RawHeader[] {
  const remaining = new Map<string, RawHeader[]>();
  for (const header of allHeaders) {
    const key = header.name.trim().toLowerCase();
    const list = remaining.get(key);
    if (list) {
      list.push(header);
    } else {
      remaining.set(key, [header]);
    }
  }

  const selected: RawHeader[] = [];
  for (const rawName of headerNames) {
    const key = rawName.trim().toLowerCase();
    const list = remaining.get(key);
    if (!list || list.length === 0) continue;
    // Consume from the bottom (most recently seen, physically last) first.
    selected.push(list.pop()!);
  }
  return selected;
}
