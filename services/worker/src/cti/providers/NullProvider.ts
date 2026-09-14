import { ThreatVerdict } from '@ciperscope/database';
import { ICtiProvider, CtiResult, IGeoProvider, GeoLocationResult } from './ICtiProvider';

export class NullCtiProvider implements ICtiProvider {
  public readonly name = 'NullCTI';

  public async lookup(): Promise<CtiResult> {
    return {
      status: ThreatVerdict.UNKNOWN,
      providerName: this.name,
      metadata: { reason: 'Provider unconfigured' }
    };
  }
}

export class NullGeoProvider implements IGeoProvider {
  public readonly name = 'NullGeo';

  public async lookup(): Promise<GeoLocationResult | null> {
    return null;
  }
}
