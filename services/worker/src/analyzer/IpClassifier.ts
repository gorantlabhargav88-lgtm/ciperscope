// Re-exported from @ciperscope/http-client, which is now the single shared
// implementation used by both services/worker (gates external GeoIP calls)
// and services/api (labels IPs in the intelligence API response) — moved
// there so the two services can never disagree about what counts as
// public. Kept as a re-export here (rather than updating every call site)
// so existing imports of './IpClassifier' continue to work unchanged.
export { classifyIp, type IpClassification, type IpCategory, type IpVersion } from '@ciperscope/http-client';
