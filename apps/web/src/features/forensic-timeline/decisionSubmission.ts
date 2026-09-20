export type DecisionSubmissionState = 'idle' | 'submitting' | 'success' | 'error';

/**
 * Pure guard preventing a duplicate POST while one is already in flight.
 * 'success' also blocks re-submission (the dialog closes on success —
 * see AnalystActionDialog) so a stray extra click can't double-record a
 * decision. 'error' allows a retry.
 */
export function canSubmitDecision(state: DecisionSubmissionState): boolean {
  return state === 'idle' || state === 'error';
}
