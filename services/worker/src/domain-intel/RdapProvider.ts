import { IDomainIntelProvider, DomainIntelLookupOutcome, DomainIntelResult } from './IDomainIntelProvider';
import { RdapClient, RawRdapDomainResponse } from './RdapClient';

function extractRegistrar(response: RawRdapDomainResponse): string | null {
  const registrarEntity = response.entities?.find((e) => e.roles?.includes('registrar'));
  if (!registrarEntity?.vcardArray) return null;
  const [, properties] = registrarEntity.vcardArray;
  if (!Array.isArray(properties)) return null;
  const fn = properties.find((p) => Array.isArray(p) && p[0] === 'fn');
  const value = fn?.[3];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function extractEventDate(response: RawRdapDomainResponse, action: string): Date | null {
  const event = response.events?.find((e) => e.eventAction === action);
  if (!event?.eventDate) return null;
  const parsed = new Date(event.eventDate);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function parseRdapResponse(response: RawRdapDomainResponse, rdapSource: string): DomainIntelResult {
  return {
    registrar: extractRegistrar(response),
    registrationDate: extractEventDate(response, 'registration'),
    expirationDate: extractEventDate(response, 'expiration'),
    nameservers: (response.nameservers ?? [])
      .map((ns) => ns.ldhName)
      .filter((n): n is string => typeof n === 'string' && n.length > 0),
    domainStatus: Array.isArray(response.status) ? response.status.filter((s) => typeof s === 'string') : [],
    rdapSource,
  };
}

/** Real RDAP lookup. Collects only what the registry's RDAP response
 *  actually returns — never fills in a field the response didn't provide. */
export class RdapProvider implements IDomainIntelProvider {
  public readonly name = 'rdap';
  private readonly client: RdapClient;

  constructor(client: RdapClient = new RdapClient()) {
    this.client = client;
  }

  public async lookup(registrableDomain: string): Promise<DomainIntelLookupOutcome> {
    const result = await this.client.fetchDomain(registrableDomain);
    switch (result.outcome) {
      case 'SUCCESS':
        return { status: 'SUCCESS', data: parseRdapResponse(result.response, result.rdapSource) };
      case 'NOT_FOUND':
        return { status: 'NOT_FOUND', data: null };
      case 'PROVIDER_TIMEOUT':
        return { status: 'PROVIDER_TIMEOUT', data: null };
      case 'PROVIDER_ERROR':
        return { status: 'PROVIDER_ERROR', data: null, errorMessage: result.errorMessage };
    }
  }
}
