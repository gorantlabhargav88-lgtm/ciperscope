import { CTIEnrichmentJob, validateCTIJob } from '@ciperscope/queue/src/cti-job';

export async function processCTIJob(jobData: any) {
  if (!validateCTIJob(jobData)) {
    throw new Error('Malformed CTI job payload');
  }

  // Idempotent execution
  // In production, this would call the decoupled CTI provider from @ciperscope/providers
  let result;
  switch (jobData.indicatorType) {
    case 'DOMAIN':
      result = { status: 'available' };
      break;
    case 'IP':
      result = { status: 'available' };
      break;
    case 'HASH':
      result = { status: 'available' };
      break;
    default:
      // Ignore unsupported indicators safely
      result = { status: 'unsupported' };
  }

  return result;
}
