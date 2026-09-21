import { CTIEnrichmentJob, validateCTIJob } from '@ciperscope/queue/src/cti-job';
import { PrismaClient, IndicatorType } from '@ciperscope/database';
import { ctiProvider } from '@ciperscope/providers';
import { createLogger } from '@ciperscope/logger';

const logger = createLogger('cti-worker');

export async function processCTIJob(jobData: CTIEnrichmentJob) {
  const startTime = Date.now();
  if (!validateCTIJob(jobData)) {
    logger.error({ jobData }, 'Malformed CTI job payload');
    throw new Error('Malformed CTI job payload');
  }

  const { indicator, indicatorType } = jobData;
  logger.info({ indicatorType }, 'Starting CTI enrichment job');

  let result;
  try {
    if (indicatorType === 'IP') {
      result = await ctiProvider.enrichIp(indicator);
    } else if (indicatorType === 'DOMAIN') {
      result = await ctiProvider.enrichDomain(indicator);
    } else {
      result = await ctiProvider.enrichHash(indicator);
    }
  } catch (error: unknown) {
    logger.error({ error: error instanceof Error ? error.message : 'Unknown error', indicatorType }, 'CTI provider execution failed');
    throw error;
  }

  const ctiData = result.data;
  if (!ctiData) {
    logger.warn({ status: result.status, indicatorType }, 'CTI provider returned no data');
    return { status: result.status, verdict: 'UNKNOWN' };
  }

  // Use dynamic instantiation to prevent top-level native addon crashes in isolated unit test environments
  const prisma = new PrismaClient();
  try {
    let dbIndicator = await prisma.indicator.findUnique({ where: { value: indicator } });
    if (!dbIndicator) {
       dbIndicator = await prisma.indicator.create({
           data: {
               type: indicatorType as IndicatorType,
               value: indicator,
           }
       });
    }

    const provider = ctiData.provider || 'System';
    
    const existingObservation = await prisma.threatIntelObservation.findFirst({
        where: {
            indicatorId: dbIndicator.id,
            provider
        }
    });

    if (!existingObservation) {
       await prisma.threatIntelObservation.create({
           data: {
               indicatorId: dbIndicator.id,
               provider,
               verdict: ctiData.verdict || 'UNKNOWN',
               confidence: ctiData.confidence || 0,
               rawResponse: { status: ctiData.status, latencyMs: ctiData.latencyMs, cached: !!ctiData.fromCache },
               observationTime: new Date()
           }
       });
    } else {
       const ONE_DAY_MS = 24 * 60 * 60 * 1000;
       const isStale = Date.now() - existingObservation.observationTime.getTime() > ONE_DAY_MS;
       if (isStale || existingObservation.verdict !== ctiData.verdict) {
           await prisma.threatIntelObservation.update({
               where: { id: existingObservation.id },
               data: {
                   verdict: ctiData.verdict || 'UNKNOWN',
                   confidence: ctiData.confidence || 0,
                   rawResponse: { status: ctiData.status, latencyMs: ctiData.latencyMs, cached: !!ctiData.fromCache },
                   observationTime: new Date()
               }
           });
       }
    }
  } catch (dbError: unknown) {
    logger.error({ error: dbError instanceof Error ? dbError.message : 'Unknown error' }, 'Failed to persist CTI observation');
    throw dbError;
  } finally {
    await prisma.$disconnect();
  }

  const latencyMs = Date.now() - startTime;
  logger.info({ 
    indicatorType, 
    provider: ctiData.provider, 
    verdict: ctiData.verdict,
    latencyMs,
    cacheHit: !!ctiData.fromCache 
  }, 'CTI enrichment job completed successfully');

  return { status: ctiData.status, verdict: ctiData.verdict };
}
