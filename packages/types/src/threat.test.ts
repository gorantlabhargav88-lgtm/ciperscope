import { describe, it, expect } from 'vitest';
import { calculateThreatPriority, ThreatPrioritySignals } from './threat';

function signals(overrides: Partial<ThreatPrioritySignals>): ThreatPrioritySignals {
  return {
    severity: null,
    threatScore: null,
    maliciousIndicatorCount: 0,
    authenticationFailed: false,
    mlClassification: null,
    ...overrides,
  };
}

describe('calculateThreatPriority', () => {
  it('harmless email (LOW severity, low score, no signals) is P3', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 5 }));
    expect(result.priority).toBe('P3');
  });

  it('email with no risk assessment yet (all nulls) is P3, not a guess', () => {
    const result = calculateThreatPriority(signals({}));
    expect(result.priority).toBe('P3');
    expect(result.reasons[0]).toContain('UNKNOWN');
  });

  it('suspicious email (MEDIUM severity, moderate score) is P3', () => {
    const result = calculateThreatPriority(signals({ severity: 'MEDIUM', threatScore: 45 }));
    expect(result.priority).toBe('P3');
  });

  it('MEDIUM severity + failed auth + malicious indicator escalates to P2', () => {
    const result = calculateThreatPriority(
      signals({ severity: 'MEDIUM', threatScore: 40, authenticationFailed: true, maliciousIndicatorCount: 1 })
    );
    expect(result.priority).toBe('P2');
  });

  it('failed auth alone (no malicious indicator) does NOT escalate priority', () => {
    const result = calculateThreatPriority(
      signals({ severity: 'LOW', threatScore: 10, authenticationFailed: true, maliciousIndicatorCount: 0 })
    );
    expect(result.priority).toBe('P3');
  });

  it('HIGH severity is P2 even with a low score and no other signals', () => {
    const result = calculateThreatPriority(signals({ severity: 'HIGH', threatScore: 10 }));
    expect(result.priority).toBe('P2');
  });

  it('threat score boundary: exactly 60 is P2', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 60 }));
    expect(result.priority).toBe('P2');
  });

  it('threat score boundary: 59 is not enough alone for P2', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 59 }));
    expect(result.priority).toBe('P3');
  });

  it('CRITICAL severity alone (no corroborating signal, low score) is P2, not P1', () => {
    const result = calculateThreatPriority(signals({ severity: 'CRITICAL', threatScore: 30 }));
    expect(result.priority).toBe('P2');
  });

  it('CRITICAL severity + malicious indicator is P1', () => {
    const result = calculateThreatPriority(
      signals({ severity: 'CRITICAL', threatScore: 30, maliciousIndicatorCount: 1 })
    );
    expect(result.priority).toBe('P1');
  });

  it('CRITICAL severity + malicious ML classification (BEC) is P1', () => {
    const result = calculateThreatPriority(
      signals({ severity: 'CRITICAL', threatScore: 30, mlClassification: 'BEC' })
    );
    expect(result.priority).toBe('P1');
  });

  it('boundary: CRITICAL severity + score exactly 80 is P1', () => {
    const result = calculateThreatPriority(signals({ severity: 'CRITICAL', threatScore: 80 }));
    expect(result.priority).toBe('P1');
  });

  it('boundary: CRITICAL severity + score 79 (no other signal) is P2', () => {
    const result = calculateThreatPriority(signals({ severity: 'CRITICAL', threatScore: 79 }));
    expect(result.priority).toBe('P2');
  });

  it('high-risk phishing email: CRITICAL severity, high score, malicious indicators, ML-flagged PHISHING is P1', () => {
    const result = calculateThreatPriority(
      signals({
        severity: 'CRITICAL',
        threatScore: 92,
        maliciousIndicatorCount: 3,
        authenticationFailed: true,
        mlClassification: 'PHISHING',
      })
    );
    expect(result.priority).toBe('P1');
    expect(result.reasons.length).toBeGreaterThan(0);
  });

  it('extreme score alone (>= 90) is always P1, even with LOW severity', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 95 }));
    expect(result.priority).toBe('P1');
  });

  it('boundary: score exactly 90 is P1', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 90 }));
    expect(result.priority).toBe('P1');
  });

  it('boundary: score 89 with LOW severity is P2 (score >= 60 rule), not P1 (needs >= 90)', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 89 }));
    expect(result.priority).toBe('P2');
  });

  it('boundary: score 59 with LOW severity stays P3 — just under both the P1 and P2 score thresholds', () => {
    const result = calculateThreatPriority(signals({ severity: 'LOW', threatScore: 59 }));
    expect(result.priority).toBe('P3');
  });

  it('a benign ML classification (LEGITIMATE) does not count as malicious corroboration', () => {
    const result = calculateThreatPriority(
      signals({ severity: 'CRITICAL', threatScore: 30, mlClassification: 'LEGITIMATE' })
    );
    expect(result.priority).toBe('P2');
  });

  it('is deterministic and pure — same input always yields the same output', () => {
    const input = signals({ severity: 'HIGH', threatScore: 70, maliciousIndicatorCount: 2 });
    const first = calculateThreatPriority(input);
    const second = calculateThreatPriority(input);
    expect(first).toEqual(second);
  });

  it('missing/invalid optional data (undefined mlClassification) does not throw', () => {
    expect(() =>
      calculateThreatPriority({
        severity: 'MEDIUM',
        threatScore: 50,
        maliciousIndicatorCount: 0,
        authenticationFailed: false,
      })
    ).not.toThrow();
  });
});
