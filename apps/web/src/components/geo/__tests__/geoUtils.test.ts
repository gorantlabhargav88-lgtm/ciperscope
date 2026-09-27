import { describe, it, expect } from 'vitest';
import {
  isValidCoordinate,
  kmToMeters,
  formatCoordinates,
  formatAccuracyRadius,
  filterPublicLocatedIps,
} from '../geoUtils';
import type { NetworkIntelligenceItem } from '@ciperscope/types';

describe('GeoIntelligence Utilities (Unit Tests)', () => {
  describe('1. Valid coordinates', () => {
    it('accepts valid latitude and longitude numbers within bounds', () => {
      expect(isValidCoordinate(37.751, -97.822)).toBe(true);
      expect(isValidCoordinate(0, 0)).toBe(true);
      expect(isValidCoordinate(90, 180)).toBe(true);
      expect(isValidCoordinate(-90, -180)).toBe(true);
      expect(isValidCoordinate(51.5074, -0.1278)).toBe(true);
    });
  });

  describe('2. Invalid coordinates', () => {
    it('rejects NaN, Infinity, and non-number values', () => {
      expect(isValidCoordinate(NaN, -97.822)).toBe(false);
      expect(isValidCoordinate(37.751, NaN)).toBe(false);
      expect(isValidCoordinate(Infinity, 0)).toBe(false);
      expect(isValidCoordinate(0, -Infinity)).toBe(false);
      expect(isValidCoordinate(null, 10)).toBe(false);
      expect(isValidCoordinate(10, undefined)).toBe(false);
      expect(isValidCoordinate('37.751', '-97.822')).toBe(false);
    });

    it('rejects coordinates exceeding Earth latitude/longitude limits', () => {
      expect(isValidCoordinate(90.001, 0)).toBe(false);
      expect(isValidCoordinate(-90.001, 0)).toBe(false);
      expect(isValidCoordinate(0, 180.001)).toBe(false);
      expect(isValidCoordinate(0, -180.001)).toBe(false);
      expect(isValidCoordinate(999, 999)).toBe(false);
    });
  });

  describe('3. Single IP handling', () => {
    it('correctly parses and validates a single public IP record', () => {
      const items: NetworkIntelligenceItem[] = [
        {
          ip: '104.244.42.1',
          version: 'v4',
          classification: 'Public',
          isRoutablePublic: true,
          hopCount: 2,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: ['eml-1'],
          relatedEmailCount: 1,
          receivedHopHostnames: ['relay.example.com'],
          reverseDns: ['relay.twitter.com'],
          geolocation: {
            country: 'United States',
            region: null,
            city: null,
            latitude: 37.751,
            longitude: -97.822,
            asn: 'AS13414',
            isp: 'Twitter Inc.',
            provider: 'MaxMind',
            updatedAt: '2026-09-26T15:28:54Z',
            accuracyRadius: 1000,
          },
        },
      ];

      const result = filterPublicLocatedIps(items);
      expect(result).toHaveLength(1);
      expect(result[0].ip).toBe('104.244.42.1');
      expect(result[0].latitude).toBe(37.751);
      expect(result[0].longitude).toBe(-97.822);
      expect(result[0].accuracyRadiusKm).toBe(1000);
      expect(result[0].accuracyRadiusMeters).toBe(1_000_000);
      expect(result[0].provider).toBe('MaxMind');
    });
  });

  describe('4. Multiple IPs handling', () => {
    it('processes multiple public located IPs cleanly', () => {
      const items: NetworkIntelligenceItem[] = [
        {
          ip: '104.244.42.1',
          version: 'v4',
          classification: 'Public',
          isRoutablePublic: true,
          hopCount: 1,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: {
            country: 'United States',
            region: 'Kansas',
            city: null,
            latitude: 37.751,
            longitude: -97.822,
            asn: 'AS13414',
            isp: 'Twitter Inc.',
            provider: 'MaxMind',
            updatedAt: '2026-09-26T15:28:54Z',
            accuracyRadius: 1000,
          },
        },
        {
          ip: '140.82.121.4',
          version: 'v4',
          classification: 'Public',
          isRoutablePublic: true,
          hopCount: 3,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T16:00:00Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: {
            country: 'United States',
            region: 'California',
            city: 'San Francisco',
            latitude: 37.7749,
            longitude: -122.4194,
            asn: 'AS36459',
            isp: 'GitHub, Inc.',
            provider: 'MaxMind',
            updatedAt: '2026-09-26T16:00:00Z',
            accuracyRadius: 20,
          },
        },
      ];

      const result = filterPublicLocatedIps(items);
      expect(result).toHaveLength(2);
      expect(result.map((r) => r.ip)).toEqual(['104.244.42.1', '140.82.121.4']);
      expect(result[1].city).toBe('San Francisco');
      expect(result[1].accuracyRadiusMeters).toBe(20_000);
    });
  });

  describe('5. Missing coordinates handling', () => {
    it('omits public IPs that do not have coordinates yet', () => {
      const items: NetworkIntelligenceItem[] = [
        {
          ip: '1.2.3.4',
          version: 'v4',
          classification: 'Public',
          isRoutablePublic: true,
          hopCount: 1,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: {
            country: 'US',
            region: null,
            city: 'Seattle',
            latitude: null, // missing coordinate
            longitude: null,
            asn: 'AS1234',
            isp: 'Test ISP',
            provider: 'MaxMind',
            updatedAt: '2026-09-18T06:14:53Z',
          },
        },
        {
          ip: '8.8.8.8',
          version: 'v4',
          classification: 'Public',
          isRoutablePublic: true,
          hopCount: 1,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: null, // completely unenriched
        },
      ];

      const result = filterPublicLocatedIps(items);
      expect(result).toHaveLength(0);
    });
  });

  describe('6. Private, loopback, and local IP exclusion', () => {
    it('strictly excludes private (RFC 1918), loopback, and non-routable IPs even if geolocation object exists', () => {
      const items: NetworkIntelligenceItem[] = [
        {
          ip: '192.168.1.1',
          version: 'v4',
          classification: 'Private (RFC 1918)',
          isRoutablePublic: false,
          hopCount: 1,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: {
            country: 'Local',
            region: null,
            city: null,
            latitude: 37.751,
            longitude: -97.822,
            asn: null,
            isp: null,
            provider: 'MaxMind',
            updatedAt: '2026-09-26T15:28:54Z',
          },
        },
        {
          ip: '127.0.0.1',
          version: 'v4',
          classification: 'Loopback',
          isRoutablePublic: false,
          hopCount: 1,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: null,
        },
        {
          ip: '10.0.0.1',
          version: 'v4',
          classification: 'Private (RFC 1918)',
          isRoutablePublic: false,
          hopCount: 1,
          firstSeen: '2026-09-20T00:00:00Z',
          lastSeen: '2026-09-26T15:28:54Z',
          relatedEmailIds: [],
          relatedEmailCount: 0,
          receivedHopHostnames: [],
          reverseDns: null,
          geolocation: null,
        },
      ];

      const result = filterPublicLocatedIps(items);
      expect(result).toHaveLength(0);
    });
  });

  describe('7. Accuracy radius conversion & formatting', () => {
    it('converts kilometers to meters accurately', () => {
      expect(kmToMeters(1000)).toBe(1_000_000);
      expect(kmToMeters(20)).toBe(20_000);
      expect(kmToMeters(5)).toBe(5000);
      expect(kmToMeters(0.5)).toBe(500);
      expect(kmToMeters(null)).toBeNull();
      expect(kmToMeters(undefined)).toBeNull();
      expect(kmToMeters(0)).toBeNull();
      expect(kmToMeters(-10)).toBeNull();
    });

    it('formats coordinates and radius for human-readable display', () => {
      expect(formatCoordinates(37.751, -97.822)).toBe('37.7510° N, 97.8220° W');
      expect(formatCoordinates(-33.8688, 151.2093)).toBe('33.8688° S, 151.2093° E');
      expect(formatAccuracyRadius(1000)).toBe('±1,000 km (Approximate)');
      expect(formatAccuracyRadius(20)).toBe('±20 km (Approximate)');
      expect(formatAccuracyRadius(null)).toBe('Approximate (unspecified radius)');
    });
  });
});
