import { describe, it, expect } from 'vitest';
import {
  computeUniversalIndicators,
  computeApkIndicators,
  calculateEntropy,
} from '../AttachmentThreatIndicators';
import { ApkStaticAnalysis, APK_ANALYZER_VERSION } from '../apk/ApkAnalyzer';

function baseUniversalInput(overrides: Partial<Parameters<typeof computeUniversalIndicators>[0]> = {}) {
  return {
    filename: 'invoice.pdf',
    declaredMimeType: 'application/pdf',
    actualMimeType: 'application/pdf',
    isMismatch: false,
    isArchive: false,
    archiveHasTraversal: false,
    archiveHasNestedArchive: false,
    archiveError: null,
    entropy: 3.0,
    ...overrides,
  };
}

function baseApk(overrides: Partial<ApkStaticAnalysis> = {}): ApkStaticAnalysis {
  return {
    packageName: 'com.example.app',
    versionCode: '1',
    versionName: '1.0',
    minSdkVersion: '21',
    targetSdkVersion: '33',
    permissions: [],
    suspiciousPermissions: [],
    activities: [],
    services: [],
    receivers: [],
    providers: [],
    embeddedUrls: [],
    hasClassesDex: true,
    nativeLibraries: [],
    signing: { hasV1JarSigning: true, hasV2SigningBlock: false, signingFiles: ['META-INF/CERT.RSA'] },
    manifestParseError: null,
    analyzerVersion: APK_ANALYZER_VERSION,
    ...overrides,
  };
}

describe('calculateEntropy', () => {
  it('returns 0 for an empty buffer', () => {
    expect(calculateEntropy(Buffer.alloc(0))).toBe(0);
  });

  it('returns 0 for a buffer of a single repeated byte (no randomness)', () => {
    expect(calculateEntropy(Buffer.alloc(1000, 0x41))).toBe(0);
  });

  it('returns close to 8 bits/byte for uniformly random-looking data', () => {
    const buf = Buffer.alloc(4096);
    for (let i = 0; i < buf.length; i++) buf[i] = i % 256; // full 0-255 spread, maximal entropy
    expect(calculateEntropy(buf)).toBeGreaterThan(7.9);
  });
});

describe('computeUniversalIndicators', () => {
  it('does not flag a normal, well-formed attachment', () => {
    const indicators = computeUniversalIndicators(baseUniversalInput());
    expect(indicators).toEqual([]);
  });

  it('flags a commonly-abused suspicious extension', () => {
    const indicators = computeUniversalIndicators(baseUniversalInput({ filename: 'invoice.exe' }));
    expect(indicators.some((i) => i.category === 'SUSPICIOUS_EXTENSION')).toBe(true);
  });

  it('flags a MIME/extension mismatch as high severity', () => {
    const indicators = computeUniversalIndicators(
      baseUniversalInput({ isMismatch: true, actualMimeType: 'application/x-msdownload' })
    );
    const finding = indicators.find((i) => i.category === 'MIME_EXTENSION_MISMATCH');
    expect(finding?.severity).toBe('HIGH');
  });

  it('flags archive path traversal as critical', () => {
    const indicators = computeUniversalIndicators(baseUniversalInput({ isArchive: true, archiveHasTraversal: true }));
    const finding = indicators.find((i) => i.category === 'ARCHIVE_PATH_TRAVERSAL');
    expect(finding?.severity).toBe('CRITICAL');
  });

  it('flags an archive safety-limit error (e.g. zip-bomb protection tripped)', () => {
    const indicators = computeUniversalIndicators(
      baseUniversalInput({ isArchive: true, archiveError: 'Exceeded max uncompressed size' })
    );
    expect(indicators.some((i) => i.category === 'ARCHIVE_SAFETY_LIMIT_EXCEEDED')).toBe(true);
  });

  it('flags high entropy for a non-archive, non-compressed file', () => {
    const indicators = computeUniversalIndicators(
      baseUniversalInput({ filename: 'notes.txt', entropy: 7.9, isArchive: false })
    );
    expect(indicators.some((i) => i.category === 'HIGH_ENTROPY_CONTENT')).toBe(true);
  });

  it('does not flag high entropy for a declared archive (compression naturally has high entropy)', () => {
    const indicators = computeUniversalIndicators(
      baseUniversalInput({ filename: 'bundle.zip', entropy: 7.9, isArchive: true })
    );
    expect(indicators.some((i) => i.category === 'HIGH_ENTROPY_CONTENT')).toBe(false);
  });
});

describe('computeApkIndicators', () => {
  it('does not flag a clean, signed APK with only benign permissions', () => {
    const indicators = computeApkIndicators(baseApk());
    expect(indicators).toEqual([]);
  });

  it('flags 3+ dangerous permissions as HIGH severity', () => {
    const indicators = computeApkIndicators(baseApk({
      permissions: ['android.permission.SEND_SMS', 'android.permission.READ_SMS', 'android.permission.CALL_PHONE'],
      suspiciousPermissions: ['android.permission.SEND_SMS', 'android.permission.READ_SMS', 'android.permission.CALL_PHONE'],
    }));
    const finding = indicators.find((i) => i.category === 'APK_SUSPICIOUS_PERMISSIONS');
    expect(finding?.severity).toBe('HIGH');
  });

  it('flags an unsigned APK', () => {
    const indicators = computeApkIndicators(baseApk({
      signing: { hasV1JarSigning: false, hasV2SigningBlock: false, signingFiles: [] },
    }));
    expect(indicators.some((i) => i.category === 'APK_UNSIGNED')).toBe(true);
  });

  it('does not flag signing when a v2 signing block is present even without v1 files', () => {
    const indicators = computeApkIndicators(baseApk({
      signing: { hasV1JarSigning: false, hasV2SigningBlock: true, signingFiles: [] },
    }));
    expect(indicators.some((i) => i.category === 'APK_UNSIGNED')).toBe(false);
  });

  it('flags a manifest parse error', () => {
    const indicators = computeApkIndicators(baseApk({ manifestParseError: 'AXML: malformed chunk header' }));
    expect(indicators.some((i) => i.category === 'APK_MALFORMED_MANIFEST')).toBe(true);
  });

  it('flags embedded URLs and exported components independently', () => {
    const indicators = computeApkIndicators(baseApk({
      embeddedUrls: ['https://evil.example.com'],
      activities: [{ name: 'com.example.Main', exported: true }],
    }));
    expect(indicators.some((i) => i.category === 'APK_EMBEDDED_URLS')).toBe(true);
    expect(indicators.some((i) => i.category === 'APK_EXPORTED_COMPONENTS')).toBe(true);
  });

  it('never invents a verdict — indicators are always evidence-labeled, not a malicious/benign classification', () => {
    const indicators = computeApkIndicators(baseApk({
      suspiciousPermissions: ['android.permission.SEND_SMS'],
    }));
    for (const i of indicators) {
      expect(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).toContain(i.severity);
      expect(i.source).toBeTruthy();
      expect(i.analyzerVersion).toBeTruthy();
      expect(i.description).not.toMatch(/malicious|confirmed threat/i);
    }
  });
});
