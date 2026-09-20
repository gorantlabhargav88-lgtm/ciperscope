import { describe, it, expect } from 'vitest';
import { normalizeAuthResult, isAuthResultPass } from './authentication';

describe('normalizeAuthResult', () => {
  it('accepts real backend uppercase values as-is', () => {
    expect(normalizeAuthResult('PASS')).toBe('PASS');
    expect(normalizeAuthResult('FAIL')).toBe('FAIL');
    expect(normalizeAuthResult('SOFTFAIL')).toBe('SOFTFAIL');
    expect(normalizeAuthResult('NEUTRAL')).toBe('NEUTRAL');
    expect(normalizeAuthResult('NONE')).toBe('NONE');
    expect(normalizeAuthResult('TEMPERROR')).toBe('TEMPERROR');
    expect(normalizeAuthResult('PERMERROR')).toBe('PERMERROR');
  });

  it('tolerates lowercase and mixed case', () => {
    expect(normalizeAuthResult('pass')).toBe('PASS');
    expect(normalizeAuthResult('fail')).toBe('FAIL');
    expect(normalizeAuthResult('Neutral')).toBe('NEUTRAL');
  });

  it('maps null/undefined/empty to UNKNOWN, not a fabricated status', () => {
    expect(normalizeAuthResult(null)).toBe('UNKNOWN');
    expect(normalizeAuthResult(undefined)).toBe('UNKNOWN');
    expect(normalizeAuthResult('')).toBe('UNKNOWN');
  });

  it('maps an unrecognized string to UNKNOWN rather than inventing a status', () => {
    expect(normalizeAuthResult('bogus')).toBe('UNKNOWN');
    expect(normalizeAuthResult('unknown')).toBe('UNKNOWN');
  });
});

describe('isAuthResultPass', () => {
  it('is true only for PASS in any case', () => {
    expect(isAuthResultPass('PASS')).toBe(true);
    expect(isAuthResultPass('pass')).toBe(true);
  });

  it('is false for FAIL, NEUTRAL, and unknown/null', () => {
    expect(isAuthResultPass('FAIL')).toBe(false);
    expect(isAuthResultPass('fail')).toBe(false);
    expect(isAuthResultPass('NEUTRAL')).toBe(false);
    expect(isAuthResultPass(null)).toBe(false);
    expect(isAuthResultPass(undefined)).toBe(false);
  });
});
