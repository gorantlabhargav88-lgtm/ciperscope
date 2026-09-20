import type { ForensicTimelineCategory, ForensicTimelineEvent } from '@ciperscope/types';

export interface PreparedForensicTimeline {
  events: ForensicTimelineEvent[];
  /** Only categories actually present in `events` — never a fabricated empty bucket. */
  availableCategories: ForensicTimelineCategory[];
}

const CATEGORY_ORDER: ForensicTimelineCategory[] = [
  'EMAIL',
  'AUTHENTICATION',
  'THREAT_INTELLIGENCE',
  'ML',
  'INVESTIGATION',
  'EVIDENCE',
  'ANALYST',
  'SYSTEM',
];

/**
 * Prepares the raw GET /cases/:caseId/forensic-timeline response for
 * display: drops malformed entries (missing id/category/action), removes
 * duplicate ids, sorts chronologically (oldest first — this timeline tells
 * an investigation's story, unlike the newest-first activity-log style of
 * CaseForensicTimeline), and computes which filter categories genuinely
 * have data.
 */
export function prepareForensicTimeline(events: ForensicTimelineEvent[]): PreparedForensicTimeline {
  const seen = new Set<string>();
  const valid: ForensicTimelineEvent[] = [];

  for (const event of events) {
    if (!event || !event.id || !event.category || !event.action) continue;
    if (seen.has(event.id)) continue;
    seen.add(event.id);
    valid.push(event);
  }

  valid.sort((a, b) => {
    if (a.timestamp === null && b.timestamp === null) return 0;
    if (a.timestamp === null) return 1;
    if (b.timestamp === null) return -1;
    return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
  });

  const present = new Set(valid.map((e) => e.category));
  const availableCategories = CATEGORY_ORDER.filter((c) => present.has(c));

  return { events: valid, availableCategories };
}

export function filterByCategory(
  events: ForensicTimelineEvent[],
  category: ForensicTimelineCategory | 'ALL'
): ForensicTimelineEvent[] {
  if (category === 'ALL') return events;
  return events.filter((e) => e.category === category);
}
