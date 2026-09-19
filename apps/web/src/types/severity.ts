/**
 * Mirrors enums defined in packages/database/prisma/schema.prisma. Kept as hand-written
 * local types (not generated) until packages/types is populated as a real shared package.
 */

/** Case.priority / Case.severity / RiskAssessment.riskLevel */
export type Priority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** Alert.severity — a separate enum from Priority, includes INFO */
export type AlertSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/** SPF / DKIM / DMARC verdicts */
export type AuthResultStatus = 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR';

export type CaseStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export type ThreatVerdict = 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

/**
 * CiperScope has no P1/P2/P3 concept in the backend — this is a presentation-only mapping
 * over the real `Priority` enum: P1 = CRITICAL, P2 = HIGH, P3 = MEDIUM or LOW.
 */
export type PriorityTier = 'P1' | 'P2' | 'P3';

export function toPriorityTier(priority: Priority): PriorityTier {
  if (priority === 'CRITICAL') return 'P1';
  if (priority === 'HIGH') return 'P2';
  return 'P3';
}
