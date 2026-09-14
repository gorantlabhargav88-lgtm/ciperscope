import { describe, it, expect } from 'vitest';
import { NullCtiProvider, NullGeoProvider } from '../NullProvider';
import { ThreatVerdict, IndicatorType } from '@ciperscope/database';

describe('NullProviders', () => {
  it('NullCtiProvider returns UNKNOWN without fake verdicts', async () => {
    const provider = new NullCtiProvider();
    const result = await provider.lookup({ type: IndicatorType.IP, value: '127.0.0.1' });

    expect(result.status).toBe(ThreatVerdict.UNKNOWN);
    expect(result.providerName).toBe('NullCTI');
  });

  it('NullGeoProvider returns null', async () => {
    const provider = new NullGeoProvider();
    const result = await provider.lookup('127.0.0.1');

    expect(result).toBeNull();
  });
});
