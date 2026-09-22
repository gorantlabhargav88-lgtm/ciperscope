import { ThreatVerdict } from '@ciperscope/database';
import { NormalizedIoc } from '../IocNormalizer';

export interface CtiResult {
  status: ThreatVerdict;
  confidence?: number; // 0-100
  metadata?: Record<string, unknown>;
  providerName: string;
}

export interface ICtiProvider {
  readonly name: string;
  lookup(ioc: NormalizedIoc): Promise<CtiResult>;
}

export interface GeoLocationResult {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  asn?: string;
  isp?: string;
  providerName: string;
}

export interface IGeoProvider {
  readonly name: string;
  lookup(ipAddress: string): Promise<GeoLocationResult | null>;
}
