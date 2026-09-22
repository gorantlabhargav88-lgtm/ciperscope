import { HttpClient } from '@ciperscope/http-client';
import { logger } from '@ciperscope/logger';
import { classifyIp } from '../../analyzer/IpClassifier';
import { IGeoProvider, GeoLocationResult } from './ICtiProvider';

interface MaxMindCityResponse {
  country?: { iso_code?: string; names?: { en?: string } };
  subdivisions?: Array<{ names?: { en?: string } }>;
  city?: { names?: { en?: string } };
  location?: { latitude?: number; longitude?: number };
  traits?: {
    autonomous_system_number?: number;
    autonomous_system_organization?: string;
    isp?: string;
    organization?: string;
  };
}

/**
 * MaxMind GeoIP2 City web service (plain HTTP + Basic Auth — not the
 * downloadable .mmdb database, so no new binary dependency or license file
 * management). Matches the schema's existing `GeoLocation.provider` default
 * of "MaxMind". Gated on MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY; the caller
 * (CtiConfig) falls back to NullGeoProvider when either is absent.
 *
 * Never queries a non-public IP — this is checked here AND by the caller,
 * since a provider must never trust its caller alone for an SSRF-relevant
 * safety property.
 */
export class MaxMindGeoProvider implements IGeoProvider {
  public readonly name = 'MaxMind';
  private readonly client: HttpClient;

  constructor(
    private readonly accountId: string,
    private readonly licenseKey: string
  ) {
    this.client = new HttpClient('MaxMindGeoIP', { timeout: 5000, baseURL: 'https://geoip.maxmind.com' });
  }

  public async lookup(ipAddress: string): Promise<GeoLocationResult | null> {
    const classification = classifyIp(ipAddress);
    if (!classification.isRoutablePublic) {
      logger.warn({ ipAddress, category: classification.category }, 'Refusing to send a non-public IP to an external GeoIP provider');
      return null;
    }

    try {
      const data = await this.client.get<MaxMindCityResponse>(`/geoip/v2.1/city/${encodeURIComponent(ipAddress)}`, {
        auth: { username: this.accountId, password: this.licenseKey },
        headers: { Accept: 'application/json' },
      });

      return {
        providerName: this.name,
        country: data.country?.names?.en ?? data.country?.iso_code,
        region: data.subdivisions?.[0]?.names?.en,
        city: data.city?.names?.en,
        latitude: data.location?.latitude,
        longitude: data.location?.longitude,
        asn: data.traits?.autonomous_system_number !== undefined
          ? `AS${data.traits.autonomous_system_number}`
          : undefined,
        isp: data.traits?.isp ?? data.traits?.autonomous_system_organization ?? data.traits?.organization,
      };
    } catch (err: unknown) {
      // A 404 from MaxMind means "no data for this IP" — a legitimate,
      // non-error outcome, not a provider failure.
      const status = (err as { response?: { status?: number } })?.response?.status;
      if (status === 404) {
        return null;
      }
      // Never log the raw axios error object: it carries `config.auth`,
      // which is this provider's MaxMind license key in plaintext.
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.warn({ status, message, ipAddress }, 'MaxMind GeoIP lookup failed');
      return null;
    }
  }
}
