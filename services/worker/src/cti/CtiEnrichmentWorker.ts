import { PrismaClient, IndicatorType, Prisma } from '@ciperscope/database';
import { logger } from '@ciperscope/logger';
import { IocNormalizer, NormalizedIoc } from './IocNormalizer';
import { ReliableCtiProvider } from './providers/ReliableCtiProvider';
import { ReliableGeoProvider } from './providers/ReliableGeoProvider';

export class CtiEnrichmentWorker {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly enqueueIoc: (ioc: NormalizedIoc) => Promise<void>
  ) {}

  public async processEmail(emailId: string): Promise<void> {
    logger.info({ emailId }, 'Starting Phase 14 CTI Enrichment Fan-out');

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
    }, 'Enqueuing IOCs for CTI enrichment');

    // 3. Enqueue IOCs for decoupled asynchronous CTI worker
    for (const ioc of iocsToProcess) {
      await this.enqueueIoc(ioc);
    }

    logger.info({ emailId, iocCount: iocsToProcess.length }, 'Phase 14 CTI Fan-out completed');
  }
}

