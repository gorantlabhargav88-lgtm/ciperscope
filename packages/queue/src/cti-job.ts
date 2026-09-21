export interface CTIEnrichmentJob {
  indicator: string;
  indicatorType: 'IP' | 'DOMAIN' | 'URL' | 'HASH' | 'EMAIL_ADDRESS' | 'ASN';
  // The email that this indicator was extracted from, and its tenant. Needed
  // (Phase 7D) so the last IOC job to finish for an email can trigger exactly
  // one CTI re-evaluation of that email's risk score.
  emailId: string;
  organizationId: string;
  correlationId?: string;
}

// Ensure no secrets are leaked in payloads
export function validateCTIJob(job: any): job is CTIEnrichmentJob {
  return typeof job.indicator === 'string' && typeof job.indicatorType === 'string'
    && typeof job.emailId === 'string' && typeof job.organizationId === 'string';
}
