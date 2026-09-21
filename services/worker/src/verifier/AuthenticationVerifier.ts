import { PrismaClient, AuthResultStatus } from '@ciperscope/database';
import { RawEmailStore } from '@ciperscope/storage';
import { DnsResolver } from './DnsResolver';
import { SpfVerifier } from './SpfVerifier';
import { DkimVerifier, DkimResult } from './DkimVerifier';
import { DmarcVerifier } from './DmarcVerifier';
import { splitRawMessage, RawHeader } from './dkim/rawMessage';
import { logger } from '@ciperscope/logger';

export class AuthenticationVerifier {
  constructor(
    private prisma: PrismaClient,
    private rawEmailStore: RawEmailStore
  ) {}

  /**
   * Fetches and splits the raw message so DKIM can be verified against the
   * exact original bytes. Returns null (rather than throwing) when the raw
   * message isn't available — DKIM verification then honestly reports
   * PERMERROR instead of silently skipping or fabricating a result; SPF/DMARC
   * are unaffected since they don't need the raw bytes.
   */
  private async loadRawMessage(rawStorageKey: string | null): Promise<{ headers: RawHeader[]; body: Buffer } | null> {
    if (!rawStorageKey) return null;
    try {
      const exists = await this.rawEmailStore.exists(rawStorageKey);
      if (!exists) return null;
      const stream = await this.rawEmailStore.get(rawStorageKey);
      const chunks: Buffer[] = [];
      for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      return splitRawMessage(Buffer.concat(chunks));
    } catch (err) {
      logger.warn({ err }, 'Failed to load raw message for DKIM verification');
      return null;
    }
  }

  public async verifyEmail(emailId: string): Promise<void> {
    const resolver = new DnsResolver(50, 5000); // Max 50 lookups, 5s timeout per lookup
    const spfVerifier = new SpfVerifier(resolver);
    const dkimVerifier = new DkimVerifier(resolver);
    const dmarcVerifier = new DmarcVerifier(resolver);

    logger.info({ emailId }, 'Starting independent authentication verification');

    // 1. Gather Metadata
    const email = await this.prisma.email.findUnique({
      where: { id: emailId },
      include: {
        headers: true,
        addresses: true,
        relayHops: { orderBy: { hopOrder: 'asc' } }
      }
    });

    if (!email) {
      throw new Error(`Email ${emailId} not found`);
    }

    // 2. Determine SPF Inputs
    // Extract Return-Path
    const returnPathHeader = email.headers.find(h => h.name.toLowerCase() === 'return-path');
    let spfDomain = null;
    if (returnPathHeader) {
      const match = returnPathHeader.value.match(/<([^@>]+@)?([^>]+)>/);
      if (match) spfDomain = match[2];
    }
    if (!spfDomain && email.returnPath) {
       const parts = email.returnPath.split('@');
       spfDomain = parts.length > 1 ? parts[1] : parts[0];
    }
    
    // Determine Evaluated IP from the earliest external hop connecting to our trusted boundary
    // For this implementation, we take the last received hop (assuming it's the external sender)
    let evaluatedIp = null;
    if (email.relayHops.length > 0) {
      // Typically, the first hop in the DB (highest index / lowest hopOrder) is the boundary MTA
      const boundaryHop = email.relayHops[email.relayHops.length - 1]; 
      evaluatedIp = boundaryHop.sourceIp;
    }

    let spfResult = {
      result: 'NONE' as AuthResultStatus,
      domain: spfDomain,
      evaluatedIp,
      matchedMechanism: null as string | null,
      explanation: 'SPF inputs missing (domain or IP)'
    };

    if (spfDomain && evaluatedIp) {
      spfResult = await spfVerifier.verify(spfDomain, evaluatedIp);
    }

    // 3. Determine DKIM Inputs — cryptographic verification needs the exact
    // original message bytes, not the parsed/decoded EmailHeader rows.
    const rawMessage = await this.loadRawMessage(email.rawStorageKey);
    const claimedDkimHeaderCount = email.headers.filter(h => h.name.toLowerCase() === 'dkim-signature').length;
    const dkimSignatureHeaders = rawMessage
      ? rawMessage.headers.filter(h => h.name.trim().toLowerCase() === 'dkim-signature')
      : [];

    const dkimResults: DkimResult[] = [];
    let bestDkimResult: AuthResultStatus = 'NONE';
    let dkimDomain = null;

    if (claimedDkimHeaderCount > 0 && !rawMessage) {
      // The message claims to carry DKIM-Signature header(s) but the raw
      // bytes needed to verify them are unavailable — this is an honest
      // "could not verify", never a silent skip or a fabricated pass.
      dkimResults.push({
        result: 'PERMERROR',
        domain: null,
        selector: null,
        algorithm: null,
        bodyHashResult: 'NONE',
        explanation: 'Raw message unavailable; cannot cryptographically verify DKIM signature'
      });
      bestDkimResult = 'PERMERROR';
    }

    for (const dkimHeader of dkimSignatureHeaders) {
      const result = await dkimVerifier.verify(dkimHeader, rawMessage!.headers, rawMessage!.body);
      dkimResults.push(result);
      if (result.result === 'PASS') {
        bestDkimResult = 'PASS';
        dkimDomain = result.domain;
      } else if (bestDkimResult !== 'PASS' && result.result !== 'NONE') {
        bestDkimResult = result.result;
      }
    }

    if (dkimResults.length > 0 && !dkimDomain) {
      dkimDomain = dkimResults[0].domain;
    }

    // 4. Determine DMARC Inputs
    const fromAddress = email.addresses.find(a => a.headerName.toLowerCase() === 'from');
    let dmarcResult = {
      result: 'NONE' as AuthResultStatus,
      orgDomain: null as string | null,
      policy: null as string | null,
      subdomainPolicy: null as string | null,
      spfAlignment: null as string | null,
      dkimAlignment: null as string | null,
      explanation: 'Missing From address'
    };

    if (fromAddress && fromAddress.domain) {
      dmarcResult = await dmarcVerifier.verify(
        fromAddress.domain,
        spfResult.result === 'PASS' ? spfResult.domain : null,
        spfResult.result,
        bestDkimResult === 'PASS' ? dkimDomain : null,
        bestDkimResult
      );
    }

    // 5. Compare with claims (Authentication-Results header)
    const authResultsHeader = email.headers.find(h => h.name.toLowerCase() === 'authentication-results');
    let isConsistent = true;
    let consistencySummary = 'Verification is consistent with header claims.';

    if (authResultsHeader) {
      const claimStr = authResultsHeader.value.toLowerCase();
      const claimedSpfPass = claimStr.includes('spf=pass');
      const claimedDkimPass = claimStr.includes('dkim=pass');
      const claimedDmarcPass = claimStr.includes('dmarc=pass');
      
      const actualSpfPass = spfResult.result === 'PASS';
      const actualDkimPass = bestDkimResult === 'PASS';
      const actualDmarcPass = dmarcResult.result === 'PASS';

      if (claimedSpfPass !== actualSpfPass || claimedDkimPass !== actualDkimPass || claimedDmarcPass !== actualDmarcPass) {
        isConsistent = false;
        consistencySummary = 'Observed authentication headers conflict with independent verification.';
      }
    } else {
      consistencySummary = 'No Authentication-Results header found. Independent verification performed.';
    }

    // 6. Transactional Persistence
    const observations = resolver.getObservations();

    await this.prisma.$transaction(async (tx) => {
      // Remove existing analysis if any
      await tx.emailAuthenticationAnalysis.deleteMany({ where: { emailId } });
      await tx.spfVerification.deleteMany({ where: { emailId } });
      await tx.dkimVerification.deleteMany({ where: { emailId } });
      await tx.dmarcVerification.deleteMany({ where: { emailId } });
      await tx.dnsObservation.deleteMany({ where: { emailId } });

      await tx.emailAuthenticationAnalysis.create({
        data: {
          emailId,
          spf: spfResult.result,
          dkim: bestDkimResult,
          dmarc: dmarcResult.result,
          isConsistent,
          summary: consistencySummary
        }
      });

      await tx.spfVerification.create({
        data: {
          emailId,
          result: spfResult.result,
          domain: spfResult.domain,
          evaluatedIp: spfResult.evaluatedIp,
          matchedMechanism: spfResult.matchedMechanism,
          explanation: spfResult.explanation,
          lookups: resolver.getLookupCount()
        }
      });

      if (dkimResults.length > 0) {
        await tx.dkimVerification.createMany({
          data: dkimResults.map(dr => ({
            emailId,
            result: dr.result,
            domain: dr.domain,
            selector: dr.selector,
            algorithm: dr.algorithm,
            bodyHashResult: dr.bodyHashResult,
            explanation: dr.explanation
          }))
        });
      }

      if (dmarcResult.orgDomain) {
        await tx.dmarcVerification.create({
          data: {
            emailId,
            result: dmarcResult.result,
            orgDomain: dmarcResult.orgDomain,
            policy: dmarcResult.policy,
            subdomainPolicy: dmarcResult.subdomainPolicy,
            spfAlignment: dmarcResult.spfAlignment,
            dkimAlignment: dmarcResult.dkimAlignment,
            explanation: dmarcResult.explanation
          }
        });
      }

      if (observations.length > 0) {
        await tx.dnsObservation.createMany({
          data: observations.map(obs => ({
            emailId,
            queryName: obs.queryName,
            recordType: obs.recordType,
            response: obs.response,
            rcode: obs.rcode,
            durationMs: obs.durationMs
          }))
        });
      }
    });

    logger.info({ emailId, isConsistent }, 'Completed independent authentication verification');
  }
}
