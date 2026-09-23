import { RdapLookupStatus } from '@ciperscope/database';

export interface DomainIntelResult {
  registrar: string | null;
  registrationDate: Date | null;
  expirationDate: Date | null;
  nameservers: string[];
  domainStatus: string[];
  rdapSource: string;
}

/** `data` is populated only when `status === 'SUCCESS'` — every other
 *  status is an honest, non-fabricated reason no result is available. */
export interface DomainIntelLookupOutcome {
  status: RdapLookupStatus;
  data: DomainIntelResult | null;
  errorMessage?: string;
}

export interface IDomainIntelProvider {
  readonly name: string;
  lookup(registrableDomain: string): Promise<DomainIntelLookupOutcome>;
}
