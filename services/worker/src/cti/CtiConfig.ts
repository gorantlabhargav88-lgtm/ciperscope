
import { ICtiProvider, IGeoProvider } from './providers/ICtiProvider';
import { NullCtiProvider, NullGeoProvider } from './providers/NullProvider';
import { ReliableCtiProvider } from './providers/ReliableCtiProvider';
import { ReliableGeoProvider } from './providers/ReliableGeoProvider';
import { MaxMindGeoProvider } from './providers/MaxMindGeoProvider';
import { env } from '@ciperscope/config';
import IORedis from 'ioredis';

export class CtiConfig {
  public static getCtiProvider(redis: IORedis): ICtiProvider {
    // In future phases, we can check process.env.CTI_PROVIDER and return a real provider.
    // For Phase 14.1/14.2, we only implement the foundation (NullProvider).
    const underlying = new NullCtiProvider();
    return new ReliableCtiProvider(underlying, redis);
  }

  public static getGeoProvider(redis: IORedis): IGeoProvider {
    // Phase H: graceful degradation — a real provider only when both
    // MaxMind credentials are configured, otherwise the existing
    // NullGeoProvider (geolocation stays UNAVAILABLE, never fabricated).
    const underlying = (env.MAXMIND_ACCOUNT_ID && env.MAXMIND_LICENSE_KEY)
      ? new MaxMindGeoProvider(env.MAXMIND_ACCOUNT_ID, env.MAXMIND_LICENSE_KEY)
      : new NullGeoProvider();
    return new ReliableGeoProvider(underlying, redis);
  }
}
