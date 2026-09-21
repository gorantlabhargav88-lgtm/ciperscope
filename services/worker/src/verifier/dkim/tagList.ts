/**
 * Parses a DKIM-Signature or DKIM key-record tag list ("tag=value; tag=value; ...").
 * Per RFC 6376 §3.2, folding whitespace (FWS) between tag chunks is not part
 * of the semantic value, so all whitespace is stripped from both the tag
 * name and its value — this is correct for every tag this codebase reads
 * (b=, bh=, p=, a=, c=, d=, h=, k=, s=, v=), none of which have
 * whitespace-sensitive content.
 */
export function parseTagList(headerValue: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of headerValue.split(';')) {
    const eqIndex = part.indexOf('=');
    if (eqIndex === -1) continue;
    const key = part.slice(0, eqIndex).replace(/\s+/g, '');
    const value = part.slice(eqIndex + 1).replace(/\s+/g, '');
    if (key) tags.set(key, value);
  }
  return tags;
}
