import { DnsResolver } from './DnsResolver';
import { AuthResultStatus } from '@ciperscope/database';
import { RawHeader } from './dkim/rawMessage';
import { parseTagList } from './dkim/tagList';
import { parseDkimPublicKey, DkimKeyType, DkimPublicKeyError } from './dkim/publicKey';
import { verifyDkimCryptography, CanonicalizationMode, DkimAlgorithm } from './dkim/verifyCryptography';

export interface DkimResult {
  result: AuthResultStatus;
  domain: string | null;
  selector: string | null;
  algorithm: string | null;
  bodyHashResult: AuthResultStatus;
  explanation: string;
}

const SUPPORTED_ALGORITHMS: readonly DkimAlgorithm[] = ['rsa-sha256', 'ed25519-sha256'];
const SUPPORTED_CANONICALIZATION: readonly CanonicalizationMode[] = ['simple', 'relaxed'];

export class DkimVerifier {
  constructor(private resolver: DnsResolver) {}

  /**
   * Cryptographically verifies one DKIM-Signature header occurrence against
   * the raw message it was found in. `targetHeader` MUST be one of the
   * entries in `allHeaders` (the specific occurrence being verified — a
   * message can carry more than one DKIM-Signature header).
   *
   * Only RFC 6376 §3.7 signature verification (body hash + header signature,
   * via Node's crypto module) against the DNS-retrieved public key can ever
   * produce `result: 'PASS'`. Presence, length, or syntactic validity of the
   * signature is never sufficient.
   */
  public async verify(targetHeader: RawHeader, allHeaders: RawHeader[], body: Buffer): Promise<DkimResult> {
    const tags = parseTagList(targetHeader.value);

    const domain = tags.get('d') || null;
    const selector = tags.get('s') || null;
    const algorithmTag = tags.get('a') || null;
    const signature = tags.get('b') || null;
    const bodyHash = tags.get('bh') || null;
    const headerNamesTag = tags.get('h') || null;
    const lengthTag = tags.get('l');
    const canonicalizationTag = tags.get('c') || 'simple/simple';

    if (!domain || !selector || !signature || !bodyHash || !headerNamesTag) {
      return this.permError(domain, selector, algorithmTag, 'Missing required DKIM parameters (d, s, b, bh, or h)');
    }

    if (lengthTag !== undefined) {
      // RFC 6376's l= tag lets a signer cover only a prefix of the body,
      // which allows an attacker to append arbitrary content after a
      // validly-signed prefix while the signature still verifies. Rejecting
      // any l= tag closes this off entirely rather than implementing the
      // truncation semantics.
      return this.permError(domain, selector, algorithmTag, 'DKIM body-length tag (l=) is not supported; rejected to prevent body-truncation replay');
    }

    if (!this.isSupportedAlgorithm(algorithmTag)) {
      return this.permError(domain, selector, algorithmTag, `Unsupported DKIM algorithm: ${algorithmTag}`);
    }
    const algorithm = algorithmTag;

    const [headerAlgoRaw, bodyAlgoRaw] = canonicalizationTag.split('/');
    const headerAlgo = headerAlgoRaw || 'simple';
    const bodyAlgo = bodyAlgoRaw || 'simple';
    if (!this.isSupportedCanonicalization(headerAlgo) || !this.isSupportedCanonicalization(bodyAlgo)) {
      return this.permError(domain, selector, algorithmTag, `Unsupported canonicalization: ${canonicalizationTag}`);
    }

    try {
      const dnsQuery = `${selector}._domainkey.${domain}`;
      const txtRecords = await this.resolver.resolveTxt(dnsQuery);

      if (txtRecords.length === 0) {
        return this.permError(domain, selector, algorithm, `No public key found at ${dnsQuery}`);
      }

      const keyRecord = txtRecords.join('');
      const keyTags = parseTagList(keyRecord);
      const keyType = (keyTags.get('k') || 'rsa') as DkimKeyType;

      if (keyType !== 'rsa' && keyType !== 'ed25519') {
        return this.permError(domain, selector, algorithm, `Unsupported key type: ${keyType}`);
      }

      const expectedKeyType: DkimKeyType = algorithm === 'ed25519-sha256' ? 'ed25519' : 'rsa';
      if (keyType !== expectedKeyType) {
        return this.permError(domain, selector, algorithm, `Algorithm ${algorithm} does not match DNS key type ${keyType}`);
      }

      const pTag = keyTags.get('p');
      if (pTag === undefined) {
        return this.permError(domain, selector, algorithm, `Invalid DKIM key record at ${dnsQuery}`);
      }

      let publicKey;
      try {
        publicKey = parseDkimPublicKey(keyType, pTag);
      } catch (err) {
        const reason = err instanceof DkimPublicKeyError ? err.message : 'Malformed public key';
        return this.permError(domain, selector, algorithm, `${reason} at ${dnsQuery}`);
      }

      const outcome = verifyDkimCryptography({
        targetHeader,
        allHeaders,
        body,
        headerNames: headerNamesTag.split(':'),
        headerAlgo,
        bodyAlgo,
        expectedBodyHash: bodyHash,
        signatureBase64: signature,
        algorithm,
        publicKey
      });

      switch (outcome.status) {
        case 'PASS':
          return {
            result: 'PASS',
            domain,
            selector,
            algorithm,
            bodyHashResult: 'PASS',
            explanation: `Signature cryptographically verified using key at ${dnsQuery}`
          };
        case 'BODY_HASH_MISMATCH':
          return {
            result: 'FAIL',
            domain,
            selector,
            algorithm,
            bodyHashResult: 'FAIL',
            explanation: 'Body hash verification failed'
          };
        case 'SIGNATURE_INVALID':
          return {
            result: 'FAIL',
            domain,
            selector,
            algorithm,
            bodyHashResult: 'PASS',
            explanation: 'Cryptographic signature verification failed'
          };
        case 'MALFORMED':
          return this.permError(domain, selector, algorithm, outcome.reason);
      }
    } catch (err: unknown) {
      if ((err as Error).message === 'DNS_TIMEOUT') {
        return {
          result: 'TEMPERROR',
          domain,
          selector,
          algorithm: algorithmTag,
          bodyHashResult: 'NONE',
          explanation: 'DNS timeout fetching DKIM public key'
        };
      }
      return this.permError(domain, selector, algorithmTag, `Verification error: ${(err as Error).message}`);
    }
  }

  private isSupportedAlgorithm(value: string | null): value is DkimAlgorithm {
    return value !== null && (SUPPORTED_ALGORITHMS as readonly string[]).includes(value);
  }

  private isSupportedCanonicalization(value: string): value is CanonicalizationMode {
    return (SUPPORTED_CANONICALIZATION as readonly string[]).includes(value);
  }

  private permError(domain: string | null, selector: string | null, algorithm: string | null, explanation: string): DkimResult {
    return {
      result: 'PERMERROR',
      domain,
      selector,
      algorithm,
      bodyHashResult: 'NONE',
      explanation
    };
  }
}
