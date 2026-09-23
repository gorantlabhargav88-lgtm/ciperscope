import { CTIEnrichmentJob, validateCTIJob } from '@ciperscope/queue';
import { PrismaClient, IndicatorType } from '@ciperscope/database';
import { ctiProvider } from '@ciperscope/providers';
import { createLogger } from '@ciperscope/logger';
import { env } from '@ciperscope/config';
import IORedis from 'ioredis';
import { CtiConfig } from './cti/CtiConfig';
import { classifyIp } from './analyzer/IpClassifier';
import { DomainIntelConfig } from './domain-intel/DomainIntelConfig';
import { validateAndReduceDomain } from './domain-intel/DomainValidation';
import { DnsResolver } from './verifier/DnsResolver';

const logger = createLogger('cti-worker');

// Lazily instantiated (like the PrismaClient below) rather than at module
// load, so importing this file in an isolated unit-test environment never
// opens a real Redis connection as a side effect.
let geoProviderInstance: ReturnType<typeof CtiConfig.getGeoProvider> | null = null;
function getGeoProvider() {
  if (!geoProviderInstance) {
    const geoRedis = new IORedis(env.REDIS_URL, { maxRetriesPerRequest: null });
    geoProviderInstance = CtiConfig.getGeoProvider(geoRedis);
  }
  return geoProviderInstance;
}

let domainIntelProviderInstance: ReturnType<typeof DomainIntelConfig.getDomainIntelProvider> | null = null;
function getDomainIntelProvider() {
  if (!domainIntelProviderInstance) {
    const domainIntelRedis = new IORedis(env.REDIS_URL, { maxRetriesPerRequest: null });
    domainIntelProviderInstance = DomainIntelConfig.getDomainIntelProvider(domainIntelRedis);
  }
  return domainIntelProviderInstance;
}

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
    // Phase H: GeoIP/ASN enrichment, IP indicators only. A separate,
    // best-effort step — its failure must never fail the primary CTI
    // reputation result already persisted above, and it never sends a
    // private/reserved/loopback IP to an external provider.
    if (indicatorType === 'IP') {
      const classification = classifyIp(indicator);
      if (classification.isRoutablePublic) {
        try {
          const geo = await getGeoProvider().lookup(indicator);
          if (geo) {
            await prisma.geoLocation.upsert({
              where: { ipAddress: indicator },
              create: {
                ipAddress: indicator,
                country: geo.country,
                region: geo.region,
                city: geo.city,
                latitude: geo.latitude,
                longitude: geo.longitude,
                asn: geo.asn,
                isp: geo.isp,
                provider: geo.providerName,
              },
              update: {
                country: geo.country,
                region: geo.region,
                city: geo.city,
                latitude: geo.latitude,
                longitude: geo.longitude,
                asn: geo.asn,
                isp: geo.isp,
                provider: geo.providerName,
              },
            });
          }
        } catch (geoError: unknown) {
          logger.warn({ error: geoError instanceof Error ? geoError.message : 'Unknown error' }, 'GeoIP enrichment failed (non-fatal)');
        }
      } else {
        logger.info({ category: classification.category }, 'Skipping GeoIP lookup for a non-public IP');
      }

      // Phase N: reverse-DNS (PTR) enrichment, public IP indicators only.
      // Best-effort and attacker-influenceable (see DnsResolver.resolvePtr
      // doc comment) — never a verified identity, and its failure must
      // never fail the primary CTI result already persisted above. Uses
      // dns.reverse() directly (no HTTP), so there is no SSRF surface here.
      if (classification.isRoutablePublic) {
        try {
          const dnsResolver = new DnsResolver(5, 2000);
          await dnsResolver.resolvePtr(indicator);
          const observations = dnsResolver.getObservations();
          if (observations.length > 0) {
            // Delete+recreate inside one transaction (mirrors
            // AuthenticationVerifier's DnsObservation persistence pattern)
            // so a concurrent re-run of this same job never leaves a
            // duplicate or a momentarily-empty window.
            await prisma.$transaction([
              prisma.dnsObservation.deleteMany({
                where: { emailId: jobData.emailId, queryName: indicator, recordType: 'PTR' },
              }),
              prisma.dnsObservation.createMany({
                data: observations.map((obs) => ({
                  emailId: jobData.emailId,
                  queryName: obs.queryName,
                  recordType: obs.recordType,
                  response: obs.response,
                  rcode: obs.rcode,
                  durationMs: obs.durationMs,
                })),
              }),
            ]);
          }
        } catch (ptrError: unknown) {
          logger.warn({ error: ptrError instanceof Error ? ptrError.message : 'Unknown error' }, 'Reverse DNS (PTR) enrichment failed (non-fatal)');
        }
      }
    }

    // Phase L: RDAP domain intelligence, domain indicators only. Same
    // best-effort shape as GeoIP above — never fails the primary CTI
    // result, and never queries RDAP for a malformed/reserved domain.
    if (indicatorType === 'DOMAIN') {
      const validation = validateAndReduceDomain(indicator);
      if (!validation.ok) {
        logger.info({ domain: indicator, reason: validation.reason }, 'Skipping RDAP lookup for a non-registrable domain');
        try {
          await prisma.domainIntelligence.upsert({
            where: { registrableDomain: indicator },
            create: { registrableDomain: indicator, status: validation.reason },
            update: { status: validation.reason, fetchedAt: new Date() },
          });
        } catch (upsertError: unknown) {
          logger.warn({ error: upsertError instanceof Error ? upsertError.message : 'Unknown error' }, 'Failed to persist non-registrable domain status (non-fatal)');
        }
      } else {
        try {
          const outcome = await getDomainIntelProvider().lookup(validation.registrableDomain);
          await prisma.domainIntelligence.upsert({
            where: { registrableDomain: validation.registrableDomain },
            create: {
              registrableDomain: validation.registrableDomain,
              status: outcome.status,
              errorMessage: outcome.errorMessage ?? null,
              registrar: outcome.data?.registrar ?? null,
              registrationDate: outcome.data?.registrationDate ?? null,
              expirationDate: outcome.data?.expirationDate ?? null,
              nameservers: outcome.data?.nameservers ?? undefined,
              domainStatus: outcome.data?.domainStatus ?? undefined,
              rdapSource: outcome.data?.rdapSource ?? null,
            },
            update: {
              status: outcome.status,
              errorMessage: outcome.errorMessage ?? null,
              registrar: outcome.data?.registrar ?? null,
              registrationDate: outcome.data?.registrationDate ?? null,
              expirationDate: outcome.data?.expirationDate ?? null,
              nameservers: outcome.data?.nameservers ?? undefined,
              domainStatus: outcome.data?.domainStatus ?? undefined,
              rdapSource: outcome.data?.rdapSource ?? null,
              fetchedAt: new Date(),
            },
          });
        } catch (rdapError: unknown) {
          logger.warn({ error: rdapError instanceof Error ? rdapError.message : 'Unknown error' }, 'RDAP enrichment failed (non-fatal)');
        }
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
