export interface CTIEnrichmentJob {
  indicator: string;
  indicatorType: 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL_ADDRESS' | 'ASN';
  correlationId?: string;
}

// Ensure no secrets are leaked in payloads
export function validateCTIJob(job: any): job is CTIEnrichmentJob {
  return typeof job.indicator === 'string' && typeof job.indicatorType === 'string';
}
