import { PrismaClient, IndicatorType, Prisma } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import { IocNormalizer, NormalizedIoc } from './IocNormalizer';
import { ReliableCtiProvider } from './providers/ReliableCtiProvider';
import { ReliableGeoProvider } from './providers/ReliableGeoProvider';

export class CtiEnrichmentWorker {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly ctiProvider: ReliableCtiProvider,
    private readonly geoProvider: ReliableGeoProvider
  ) {}

  public async processEmail(emailId: string): Promise<void> {
    logger.info({ emailId }, 'Starting Phase 14 CTI Enrichment');

    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        urls: true,
        attachments: true,
        relayHops: true
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    // 1. Extract and Normalize
    const domains = new Set<string>();
    const ips = new Set<string>();
    const hashes = new Set<string>();

    for (const u of email.urls) {
      const norm = IocNormalizer.normalizeUrl(u.url);
      if (norm && norm.type === IndicatorType.DOMAIN) {
        domains.add(norm.value);
      }
    }

    for (const h of email.relayHops) {
      if (h.sourceIp) {
        const norm = IocNormalizer.normalizeIp(h.sourceIp);
        if (norm) ips.add(norm.value);
      }
    }

    for (const a of email.attachments) {
      if (a.sha256) {
        const norm = IocNormalizer.normalizeHash(a.sha256);
        if (norm) hashes.add(norm.value);
      }
    }

    // 2. Cap Fan-out limits
    const cappedDomains = Array.from(domains).slice(0, 50);
    const cappedIps = Array.from(ips).slice(0, 10);
    const cappedHashes = Array.from(hashes).slice(0, 10);

    const iocsToProcess: NormalizedIoc[] = [
      ...cappedDomains.map(d => ({ type: IndicatorType.DOMAIN, value: d })),
      ...cappedIps.map(i => ({ type: IndicatorType.IP, value: i })),
      ...cappedHashes.map(h => ({ type: IndicatorType.HASH, value: h }))
    ];

    logger.info({
      emailId,
      domains: cappedDomains.length,
      ips: cappedIps.length,
      hashes: cappedHashes.length,
      skippedDomains: Math.max(0, domains.size - 50),
      skippedIps: Math.max(0, ips.size - 10),
      skippedHashes: Math.max(0, hashes.size - 10)
    }, 'Normalized IOCs for CTI enrichment');

    // 3. Concurrently fetch CTI data (chunks of 5)
    const chunkSize = 5;
    for (let i = 0; i < iocsToProcess.length; i += chunkSize) {
      const chunk = iocsToProcess.slice(i, i + chunkSize);
      await Promise.all(chunk.map(async (ioc) => {
        // 3a. CTI Lookup
        let ctiResult;
        try {
          ctiResult = await this.ctiProvider.lookup(ioc);
        } catch (error) {
          logger.error({ err: error, ioc: ioc.value }, 'Unexpected provider error processing IOC');
          ctiResult = null;
        }

        if (ctiResult) {
          await this.prisma.threatIndicator.upsert({
            where: {
              emailId_iocValue_provider: {
                emailId,
                iocValue: ioc.value,
                provider: ctiResult.providerName
              }
            },
            update: {
              status: ctiResult.status,
              confidence: ctiResult.confidence ?? null,
              metadata: (ctiResult.metadata as unknown as Prisma.InputJsonValue) ?? {}
            },
            create: {
              emailId,
              iocType: ioc.type,
              iocValue: ioc.value,
              provider: ctiResult.providerName,
              status: ctiResult.status,
              confidence: ctiResult.confidence ?? null,
              metadata: (ctiResult.metadata as unknown as Prisma.InputJsonValue) ?? {}
            }
          });
        }

        // 3b. GEO Lookup (only for IPs)
        if (ioc.type === IndicatorType.IP) {
          let geoResult;
          try {
            geoResult = await this.geoProvider.lookup(ioc.value);
          } catch (error) {
            logger.error({ err: error, ioc: ioc.value }, 'Unexpected geo provider error processing IOC');
            geoResult = null;
          }

          if (geoResult) {
            await this.prisma.geolocationInfo.upsert({
              where: {
                emailId_ipAddress: {
                  emailId,
                  ipAddress: ioc.value
                }
              },
              update: {
                country: geoResult.country ?? null,
                city: geoResult.city ?? null,
                asn: geoResult.asn ?? null,
                isp: geoResult.isp ?? null
              },
              create: {
                emailId,
                ipAddress: ioc.value,
                country: geoResult.country ?? null,
                city: geoResult.city ?? null,
                asn: geoResult.asn ?? null,
                isp: geoResult.isp ?? null
              }
            });
          }
        }
      }));
    }

    logger.info({ emailId }, 'Phase 14 CTI Enrichment completed');
  }
}
