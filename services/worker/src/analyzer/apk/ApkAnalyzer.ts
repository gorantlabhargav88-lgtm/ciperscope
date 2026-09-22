import * as yauzl from 'yauzl';
import { parseAxml, AxmlElement } from './AxmlParser';
import { logger } from '@ciperscope/logger';

export interface ApkComponent {
  name: string;
  exported: boolean | null;
}

export interface ApkSigningIndicators {
  hasV1JarSigning: boolean;
  hasV2SigningBlock: boolean;
  signingFiles: string[];
}

export interface ApkStaticAnalysis {
  packageName: string | null;
  versionCode: string | null;
  versionName: string | null;
  minSdkVersion: string | null;
  targetSdkVersion: string | null;
  permissions: string[];
  suspiciousPermissions: string[];
  activities: ApkComponent[];
  services: ApkComponent[];
  receivers: ApkComponent[];
  providers: ApkComponent[];
  embeddedUrls: string[];
  hasClassesDex: boolean;
  nativeLibraries: string[];
  signing: ApkSigningIndicators;
  manifestParseError: string | null;
  analyzerVersion: string;
}

export const APK_ANALYZER_VERSION = '1.0.0';

// A small, curated set of Android permissions most frequently abused by
// malware (SMS fraud, accessibility-service trojans, silent installers,
// overlay/phishing attacks). Not exhaustive — extend deliberately.
const DANGEROUS_PERMISSIONS = new Set([
  'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS',
  'android.permission.READ_SMS',
  'android.permission.CALL_PHONE',
  'android.permission.PROCESS_OUTGOING_CALLS',
  'android.permission.READ_CONTACTS',
  'android.permission.RECORD_AUDIO',
  'android.permission.CAMERA',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.REQUEST_INSTALL_PACKAGES',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.BIND_DEVICE_ADMIN',
  'android.permission.RECEIVE_BOOT_COMPLETED',
  'android.permission.QUERY_ALL_PACKAGES',
  'android.permission.REQUEST_DELETE_PACKAGES',
]);

const MAX_MANIFEST_SIZE = 5 * 1024 * 1024; // 5MB — a real AndroidManifest.xml is KBs
const MAX_REPORTED_URLS = 50;
const MAX_REPORTED_NATIVE_LIBS = 50;
const URL_REGEX = /https?:\/\/[^\s"'<>]+/gi;
const APK_SIG_BLOCK_MAGIC = Buffer.from('APK Sig Block 42', 'ascii');

/**
 * Signature-based APK detection: requires AndroidManifest.xml to be present
 * as a real zip entry. No ordinary ZIP/JAR carries this exact file at this
 * path — this is far more reliable than trusting the declared filename or
 * extension.
 */
export function isLikelyApk(entryNames: string[]): boolean {
  return entryNames.includes('AndroidManifest.xml');
}

function findChildren(el: AxmlElement, name: string): AxmlElement[] {
  return el.children.filter((c) => c.name === name);
}

function getAttr(el: AxmlElement, name: string): string | null {
  return el.attributes.find((a) => a.name === name)?.value ?? null;
}

function extractComponent(el: AxmlElement): ApkComponent {
  const exportedRaw = getAttr(el, 'exported');
  return {
    name: getAttr(el, 'name') ?? 'unknown',
    exported: exportedRaw === null ? null : exportedRaw === 'true',
  };
}

function extractManifestMetadata(root: AxmlElement): Omit<
  ApkStaticAnalysis,
  'embeddedUrls' | 'hasClassesDex' | 'nativeLibraries' | 'signing' | 'manifestParseError' | 'analyzerVersion'
> {
  const permissions = findChildren(root, 'uses-permission')
    .concat(findChildren(root, 'uses-permission-sdk-23'))
    .map((el) => getAttr(el, 'name'))
    .filter((v): v is string => v !== null);

  const usesSdk = findChildren(root, 'uses-sdk')[0] ?? null;
  const application = findChildren(root, 'application')[0] ?? null;

  return {
    packageName: getAttr(root, 'package'),
    versionCode: getAttr(root, 'versionCode'),
    versionName: getAttr(root, 'versionName'),
    minSdkVersion: usesSdk ? getAttr(usesSdk, 'minSdkVersion') : null,
    targetSdkVersion: usesSdk ? getAttr(usesSdk, 'targetSdkVersion') : null,
    permissions,
    suspiciousPermissions: permissions.filter((p) => DANGEROUS_PERMISSIONS.has(p)),
    activities: application ? findChildren(application, 'activity').map(extractComponent) : [],
    services: application ? findChildren(application, 'service').map(extractComponent) : [],
    receivers: application ? findChildren(application, 'receiver').map(extractComponent) : [],
    providers: application ? findChildren(application, 'provider').map(extractComponent) : [],
  };
}

function extractEmbeddedUrls(strings: string[]): string[] {
  const found = new Set<string>();
  for (const s of strings) {
    const matches = s.match(URL_REGEX);
    if (matches) {
      for (const m of matches) {
        found.add(m);
        if (found.size >= MAX_REPORTED_URLS) return Array.from(found);
      }
    }
  }
  return Array.from(found);
}

/** Detects the APK Signing Block v2/v3 footer magic that sits immediately
 *  before the ZIP central directory. Presence indicates v2/v3 signing;
 *  absence does not by itself indicate v1 signing is present or absent. */
function detectV2SigningBlock(buffer: Buffer): boolean {
  // Locate the End Of Central Directory record (search from the end; a real
  // APK's EOCD comment is normally empty/short, so this bounded backward
  // scan is sufficient and avoids a full un-bounded search).
  const EOCD_SIG = 0x06054b50;
  const searchStart = Math.max(0, buffer.length - 65557); // max comment (0xFFFF) + EOCD size (22)
  for (let i = buffer.length - 22; i >= searchStart; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      const cdOffset = buffer.readUInt32LE(i + 16);
      if (cdOffset >= 16 && cdOffset <= buffer.length) {
        const magicSlice = buffer.subarray(cdOffset - 16, cdOffset);
        return magicSlice.equals(APK_SIG_BLOCK_MAGIC);
      }
      return false;
    }
  }
  return false;
}

function readZipEntry(buffer: Buffer, zipfile: yauzl.ZipFile, entry: yauzl.Entry): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    zipfile.openReadStream(entry, (err, stream) => {
      if (err || !stream) return reject(err ?? new Error('No stream'));
      const chunks: Buffer[] = [];
      let total = 0;
      stream.on('data', (chunk: Buffer) => {
        total += chunk.length;
        if (total > MAX_MANIFEST_SIZE) {
          stream.destroy();
          reject(new RangeError('AndroidManifest.xml exceeds safety size bound'));
          return;
        }
        chunks.push(chunk);
      });
      stream.on('end', () => resolve(Buffer.concat(chunks)));
      stream.on('error', reject);
    });
  });
}

/**
 * Statically analyzes an APK's bytes. Never executes, installs, launches, or
 * opens the APK — this reads the zip's entry table and the binary
 * AndroidManifest.xml as data only, via yauzl (a pure zip-index reader).
 *
 * Returns null if `buffer` is not a zip that looks like an APK (caller
 * should check with a magic-byte/MIME check first; this also independently
 * verifies via `isLikelyApk`).
 */
export async function analyzeApk(buffer: Buffer): Promise<ApkStaticAnalysis | null> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) return reject(err ?? new Error('Invalid zip'));

      const entryNames: string[] = [];
      const entries: yauzl.Entry[] = [];

      zipfile.on('entry', (entry: yauzl.Entry) => {
        entryNames.push(entry.fileName);
        entries.push(entry);
        zipfile.readEntry();
      });

      zipfile.on('error', reject);

      zipfile.on('end', async () => {
        if (!isLikelyApk(entryNames)) {
          resolve(null);
          return;
        }

        const hasClassesDex = entryNames.some((n) => n === 'classes.dex' || /^classes\d*\.dex$/.test(n));
        const nativeLibraries = entryNames
          .filter((n) => n.startsWith('lib/') && !n.endsWith('/'))
          .slice(0, MAX_REPORTED_NATIVE_LIBS);
        const signingFiles = entryNames.filter(
          (n) => n.startsWith('META-INF/') && (n.endsWith('.RSA') || n.endsWith('.DSA') || n.endsWith('.EC'))
        );

        let manifestMetadata: ReturnType<typeof extractManifestMetadata> | null = null;
        let embeddedUrls: string[] = [];
        let manifestParseError: string | null = null;

        try {
          // Re-open a fresh, non-lazy handle to read the one entry we need —
          // simplest safe way to random-access a single member with yauzl.
          const manifestEntry = await findAndReadManifest(buffer);
          const parsed = parseAxml(manifestEntry);
          if (parsed.root) {
            manifestMetadata = extractManifestMetadata(parsed.root);
          } else {
            manifestParseError = 'AndroidManifest.xml parsed but no root element found';
          }
          embeddedUrls = extractEmbeddedUrls(parsed.strings);
        } catch (e: unknown) {
          manifestParseError = e instanceof Error ? e.message : 'Unknown AndroidManifest.xml parse error';
          logger.warn({ err: e }, 'Failed to parse AndroidManifest.xml — reporting as malformed APK');
        }

        resolve({
          packageName: manifestMetadata?.packageName ?? null,
          versionCode: manifestMetadata?.versionCode ?? null,
          versionName: manifestMetadata?.versionName ?? null,
          minSdkVersion: manifestMetadata?.minSdkVersion ?? null,
          targetSdkVersion: manifestMetadata?.targetSdkVersion ?? null,
          permissions: manifestMetadata?.permissions ?? [],
          suspiciousPermissions: manifestMetadata?.suspiciousPermissions ?? [],
          activities: manifestMetadata?.activities ?? [],
          services: manifestMetadata?.services ?? [],
          receivers: manifestMetadata?.receivers ?? [],
          providers: manifestMetadata?.providers ?? [],
          embeddedUrls,
          hasClassesDex,
          nativeLibraries,
          signing: {
            hasV1JarSigning: signingFiles.length > 0,
            hasV2SigningBlock: detectV2SigningBlock(buffer),
            signingFiles,
          },
          manifestParseError,
          analyzerVersion: APK_ANALYZER_VERSION,
        });
      });

      zipfile.readEntry();
    });
  });
}

function findAndReadManifest(buffer: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    yauzl.fromBuffer(buffer, { lazyEntries: true }, (err, zipfile) => {
      if (err || !zipfile) return reject(err ?? new Error('Invalid zip'));
      let found = false;
      zipfile.on('entry', (entry: yauzl.Entry) => {
        if (entry.fileName === 'AndroidManifest.xml') {
          found = true;
          readZipEntry(buffer, zipfile, entry).then(resolve, reject);
          zipfile.close();
          return;
        }
        zipfile.readEntry();
      });
      zipfile.on('end', () => {
        if (!found) reject(new Error('AndroidManifest.xml entry not found'));
      });
      zipfile.on('error', reject);
      zipfile.readEntry();
    });
  });
}
