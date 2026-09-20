import type { ThreatVerdict } from './threat';

/**
 * CTI (Cyber Threat Intelligence) contract.
 * Backend mapping: packages/providers/src/cti/index.ts (`ProductionCTILayer`)
 * queries AbuseIPDB + VirusTotal only — CiperScope has no other CTI provider
 * integrated today. `status` surfaces the provider's real state honestly;
 * `not_configured` means no API key is set, not that the indicator is clean.
 */
export interface CtiResult {
  indicatorType: string;
  indicatorValue: string;
  provider: string;
  verdict: ThreatVerdict;
  confidence: number | null;
  status?: 'ok' | 'not_configured' | 'rate_limited' | 'unauthorized' | 'error';
}
