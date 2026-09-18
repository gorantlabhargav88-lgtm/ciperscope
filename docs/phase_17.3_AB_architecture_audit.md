# Phase 17.3-AB Architecture Audit

## Provider Interface
The existing `ThreatIntelligenceProvider` interface in `services/api/src/utils/cti.ts` defines methods:
- `isAvailable()`
- `enrichDomain(domain: string)`
- `enrichIp(ip: string)`
- `enrichHash(hash: string)`

This is conceptually sound but needs expansion for caching and normalized responses.

## Provider Result Contract
The `CTIResponse` contract defines:
- `status: CTIStatus`
- `data?: any`
- `provider?: string`
- `queriedAt?: string`
- `latencyMs?: number`

This contract is slightly weak because `data` is `any`. A normalized schema needs explicit fields: `indicator`, `indicatorType`, `riskScore`, `confidence`, `verdict`, `categories`, `source`, `errorCode`, `retryable`, `provenance`.

## Error Contract
`CTIStatus` enumerates errors: `'unavailable' | 'degraded' | 'not_found' | 'rate_limited' | 'unauthorized' | 'timeout' | 'provider_error'`. This is a good baseline, but it must be clearly distinct from HTTP API errors so intelligence endpoints don't crash.

## Timeout Behavior
A basic 5000ms `Promise.race` timeout exists in `withResiliency`. This is sufficient for simple boundaries but might need configurable limits per provider.

## Retry Behavior
There is currently no explicit retry logic implemented in `withResiliency`, only a fallback. Bounded exponential backoff needs to be implemented for transient errors.

## Rate-limit Behavior
Rate limiting is enumerated in `CTIStatus` but there is no backoff or circuit breaker for it.

## Provider Selection
There is currently a single mock provider (`ResilientCTIProvider`). A registry or factory pattern is needed for VirusTotal and AbuseIPDB.

## Caching Behavior
Currently, there is no cache implemented. The system needs to check a cache (Redis, as it exists in docker-compose) before querying the provider.

## Concurrency Behavior
No explicit concurrency controls for batch enrichment. If an array of IOCs is enriched, `Promise.all` could be unbounded. This needs a bounded batching mechanism.

## Logging Behavior
No structured logging is visible in the CTI wrapper. Provider lookups should emit structured diagnostics (without secrets).

## Secret Handling
No secrets are handled currently as it uses a mock provider. VirusTotal and AbuseIPDB will require environment variables (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`) and these must never be logged.
