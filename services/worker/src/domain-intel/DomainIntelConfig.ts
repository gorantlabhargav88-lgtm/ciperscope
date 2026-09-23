import IORedis from 'ioredis';
import { env } from '@ciperscope/config';
import { IDomainIntelProvider } from './IDomainIntelProvider';
import { NullDomainIntelProvider } from './NullDomainIntelProvider';
import { RdapProvider } from './RdapProvider';
import { ReliableDomainIntelProvider } from './ReliableDomainIntelProvider';

export class DomainIntelConfig {
  public static getDomainIntelProvider(redis: IORedis): IDomainIntelProvider {
    // RDAP needs no credentials (public protocol) but can still be
    // disabled entirely via env — honest NOT_CONFIGURED, never skipped
    // silently, matching CtiConfig's credential-gated pattern.
    const underlying = env.RDAP_ENABLED === 'false' ? new NullDomainIntelProvider() : new RdapProvider();
    return new ReliableDomainIntelProvider(underlying, redis);
  }
}
