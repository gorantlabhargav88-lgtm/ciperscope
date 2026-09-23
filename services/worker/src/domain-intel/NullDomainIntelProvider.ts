import { IDomainIntelProvider, DomainIntelLookupOutcome } from './IDomainIntelProvider';

/** Used when RDAP is disabled (RDAP_ENABLED=false) — honest NOT_CONFIGURED,
 *  never a fabricated result, matching NullCtiProvider/NullGeoProvider. */
export class NullDomainIntelProvider implements IDomainIntelProvider {
  public readonly name = 'null';

  public async lookup(): Promise<DomainIntelLookupOutcome> {
    return { status: 'NOT_CONFIGURED', data: null };
  }
}
