import { describe, it, expect } from 'vitest';
import { canSubmitDecision } from './decisionSubmission';

describe('canSubmitDecision', () => {
  it('idle allows submission', () => {
    expect(canSubmitDecision('idle')).toBe(true);
  });

  it('submitting blocks a duplicate submission', () => {
    expect(canSubmitDecision('submitting')).toBe(false);
  });

  it('success blocks re-submission (the dialog closes on success)', () => {
    expect(canSubmitDecision('success')).toBe(false);
  });

  it('error allows a retry', () => {
    expect(canSubmitDecision('error')).toBe(true);
  });
});
