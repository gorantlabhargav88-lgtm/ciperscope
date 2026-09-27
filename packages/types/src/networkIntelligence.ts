/**
 * Org-wide network/geo intelligence — GET /intelligence/network
 * (services/api/src/modules/intelligence/intelligence.routes.ts).
 * Aggregates RelayHop rows (tenant-scoped) with the global GeoLocation/
 * DnsObservation(PTR) tables. Backs both the Geo Intelligence and
 * Infrastructure frontend pages.
 */
export interface NetworkIntelligenceGeo {
  country: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: string | null;
  isp: string | null;
  provider: string;
  updatedAt: string;
  accuracyRadius?: number | null;
  timeZone?: string | null;
}

export interface NetworkIntelligenceItem {
  ip: string;
  version: 'v4' | 'v6' | null;
  classification: string;
  isRoutablePublic: boolean;
  hopCount: number;
  firstSeen: string;
  lastSeen: string;
  relatedEmailIds: string[];
  relatedEmailCount: number;
  receivedHopHostnames: string[];
  /** Attacker-influenceable raw forensic context, never a verified hostname — see DnsResolver.resolvePtr. */
  reverseDns: string[] | null;
  geolocation: NetworkIntelligenceGeo | null;
}

export interface NetworkIntelligenceResponse {
  items: NetworkIntelligenceItem[];
  truncated: boolean;
  /** False when no IP observed for this org has ever been enriched — distinguishes "GeoIP not configured" from "nothing public observed yet". */
  geoEnrichmentAvailable: boolean;
  /** Whether MaxMind credentials are configured in this deployment (never the credential itself) — lets the UI give the real reason geolocation is unavailable. */
  maxmindConfigured: boolean;
}
