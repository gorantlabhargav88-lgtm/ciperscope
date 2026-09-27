import type { NetworkIntelligenceItem } from '@ciperscope/types';

export interface ValidatedGeoItem {
  ip: string;
  classification: string;
  isRoutablePublic: boolean;
  latitude: number;
  longitude: number;
  country: string;
  region: string | null;
  city: string | null;
  asn: string | null;
  isp: string | null;
  accuracyRadiusKm: number | null;
  accuracyRadiusMeters: number | null;
  timeZone: string | null;
  provider: string;
  hopCount: number;
  lastSeen: string;
  firstSeen: string;
  reverseDns: string[] | null;
  relatedEmailIds: string[];
  relatedEmailCount: number;
}

/**
 * Validates latitude and longitude values.
 * Returns true if both are valid numbers, finite, not NaN,
 * with latitude in [-90, 90] and longitude in [-180, 180].
 */
export function isValidCoordinate(lat: unknown, lng: unknown): boolean {
  if (typeof lat !== 'number' || typeof lng !== 'number') return false;
  if (Number.isNaN(lat) || Number.isNaN(lng)) return false;
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return false;
  if (lat < -90 || lat > 90) return false;
  if (lng < -180 || lng > 180) return false;
  return true;
}

/**
 * Converts accuracy radius from kilometers to meters.
 * Validates that radius is a positive number.
 */
export function kmToMeters(radiusKm: number | null | undefined): number | null {
  if (radiusKm == null || typeof radiusKm !== 'number' || Number.isNaN(radiusKm) || radiusKm <= 0) {
    return null;
  }
  return Math.round(radiusKm * 1000);
}

/**
 * Formats coordinates for clean display.
 */
export function formatCoordinates(lat: number, lng: number): string {
  const latStr = `${Math.abs(lat).toFixed(4)}° ${lat >= 0 ? 'N' : 'S'}`;
  const lngStr = `${Math.abs(lng).toFixed(4)}° ${lng >= 0 ? 'E' : 'W'}`;
  return `${latStr}, ${lngStr}`;
}

/**
 * Formats accuracy radius in kilometers for display.
 */
export function formatAccuracyRadius(radiusKm: number | null | undefined): string {
  if (radiusKm == null || radiusKm <= 0) {
    return 'Approximate (unspecified radius)';
  }
  return `±${radiusKm.toLocaleString()} km (Approximate)`;
}

/**
 * Filters out private, loopback, reserved, or unlocated IPs.
 * Only returns routable public IPs with valid numeric coordinates.
 */
export function filterPublicLocatedIps(items: NetworkIntelligenceItem[] | undefined | null): ValidatedGeoItem[] {
  if (!items || !Array.isArray(items)) return [];

  const result: ValidatedGeoItem[] = [];

  for (const item of items) {
    // 1. Must be a routable public IP
    if (!item.isRoutablePublic) continue;

    // 2. Must have geolocation object
    if (!item.geolocation) continue;

    const { latitude, longitude } = item.geolocation;

    // 3. Must have valid coordinates
    if (!isValidCoordinate(latitude, longitude)) continue;

    const radiusKm = item.geolocation.accuracyRadius ?? null;
    const radiusMeters = kmToMeters(radiusKm);

    result.push({
      ip: item.ip,
      classification: item.classification,
      isRoutablePublic: item.isRoutablePublic,
      latitude: latitude as number,
      longitude: longitude as number,
      country: item.geolocation.country ?? 'Unknown',
      region: item.geolocation.region ?? null,
      city: item.geolocation.city ?? null,
      asn: item.geolocation.asn ?? null,
      isp: item.geolocation.isp ?? null,
      accuracyRadiusKm: radiusKm,
      accuracyRadiusMeters: radiusMeters,
      timeZone: item.geolocation.timeZone ?? null,
      provider: item.geolocation.provider || 'MaxMind',
      hopCount: item.hopCount,
      lastSeen: item.lastSeen,
      firstSeen: item.firstSeen,
      reverseDns: item.reverseDns,
      relatedEmailIds: item.relatedEmailIds || [],
      relatedEmailCount: item.relatedEmailCount || 0,
    });
  }

  return result;
}
