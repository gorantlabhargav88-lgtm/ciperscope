import { ApkStaticAnalysis, APK_ANALYZER_VERSION } from './apk/ApkAnalyzer';

export type ThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type ThreatConfidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface AttachmentThreatIndicator {
  category: string;
  severity: ThreatSeverity;
  description: string;
  confidence: ThreatConfidence;
  /** What produced this finding, for auditability (never a fabricated verdict). */
  source: string;
  analyzerVersion: string;
}

export const UNIVERSAL_ANALYZER_VERSION = '1.0.0';

// Extensions commonly used to deliver executable or script payloads via email.
// This flags the declared extension only — it is one input among several,
// never a standalone verdict.
const SUSPICIOUS_EXTENSIONS = new Set([
  'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse',
  'wsf', 'wsh', 'ps1', 'msi', 'dll', 'cpl', 'gadget', 'application',
  'hta', 'lnk', 'apk', 'jar',
]);

const COMPRESSED_EXTENSIONS = new Set(['zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'apk', 'jar']);
const HIGH_ENTROPY_THRESHOLD = 7.5; // bits/byte, out of a max of 8

/** Shannon entropy of a byte buffer, in bits per byte (0-8). */
export function calculateEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;
  const freq = Array.from({ length: 256 }, () => 0);
  for (const byte of buffer) freq[byte]++;
  let entropy = 0;
  for (const count of freq) {
    if (count === 0) continue;
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface UniversalIndicatorInput {
  filename: string;
  declaredMimeType: string;
  actualMimeType: string | null;
  isMismatch: boolean;
  isArchive: boolean;
  archiveHasTraversal: boolean;
  archiveHasNestedArchive: boolean;
  archiveError: string | null;
  entropy: number | null;
}

/** Deterministic, evidence-based findings — never a fabricated malware verdict. */
export function computeUniversalIndicators(input: UniversalIndicatorInput): AttachmentThreatIndicator[] {
  const indicators: AttachmentThreatIndicator[] = [];
  const ext = (input.filename.split('.').pop() ?? '').toLowerCase();

  if (SUSPICIOUS_EXTENSIONS.has(ext)) {
    indicators.push({
      category: 'SUSPICIOUS_EXTENSION',
      severity: 'MEDIUM',
      description: `Attachment "${input.filename}" has a commonly-abused extension (.${ext}).`,
      confidence: 'MEDIUM',
      source: 'AttachmentAnalyzer',
      analyzerVersion: UNIVERSAL_ANALYZER_VERSION,
    });
  }

  if (input.isMismatch) {
    indicators.push({
      category: 'MIME_EXTENSION_MISMATCH',
      severity: 'HIGH',
      description: `Declared type "${input.declaredMimeType}" does not match the file's actual signature` +
        (input.actualMimeType ? ` ("${input.actualMimeType}").` : '.'),
      confidence: 'HIGH',
      source: 'AttachmentAnalyzer',
      analyzerVersion: UNIVERSAL_ANALYZER_VERSION,
    });
  }

  if (input.archiveHasTraversal) {
    indicators.push({
      category: 'ARCHIVE_PATH_TRAVERSAL',
      severity: 'CRITICAL',
      description: 'Archive contains entries with path-traversal sequences (e.g. "../"), a technique used to overwrite files outside the intended extraction directory.',
      confidence: 'HIGH',
      source: 'AttachmentAnalyzer',
      analyzerVersion: UNIVERSAL_ANALYZER_VERSION,
    });
  }

  if (input.archiveError) {
    indicators.push({
      category: 'ARCHIVE_SAFETY_LIMIT_EXCEEDED',
      severity: 'HIGH',
      description: `Archive inspection stopped early: ${input.archiveError}`,
      confidence: 'MEDIUM',
      source: 'AttachmentAnalyzer',
      analyzerVersion: UNIVERSAL_ANALYZER_VERSION,
    });
  }

  if (input.archiveHasNestedArchive) {
    indicators.push({
      category: 'NESTED_ARCHIVE',
      severity: 'LOW',
      description: 'Archive contains another archive nested inside it.',
      confidence: 'MEDIUM',
      source: 'AttachmentAnalyzer',
      analyzerVersion: UNIVERSAL_ANALYZER_VERSION,
    });
  }

  if (
    input.entropy !== null &&
    input.entropy >= HIGH_ENTROPY_THRESHOLD &&
    !input.isArchive &&
    !COMPRESSED_EXTENSIONS.has(ext)
  ) {
    indicators.push({
      category: 'HIGH_ENTROPY_CONTENT',
      severity: 'LOW',
      description: `Content entropy (${input.entropy.toFixed(2)} bits/byte) is consistent with packed, encrypted, or obfuscated data for a file not declared as compressed.`,
      confidence: 'LOW',
      source: 'AttachmentAnalyzer',
      analyzerVersion: UNIVERSAL_ANALYZER_VERSION,
    });
  }

  return indicators;
}

export function computeApkIndicators(apk: ApkStaticAnalysis): AttachmentThreatIndicator[] {
  const indicators: AttachmentThreatIndicator[] = [];

  if (apk.manifestParseError) {
    indicators.push({
      category: 'APK_MALFORMED_MANIFEST',
      severity: 'MEDIUM',
      description: `AndroidManifest.xml could not be fully parsed: ${apk.manifestParseError}`,
      confidence: 'MEDIUM',
      source: 'ApkAnalyzer',
      analyzerVersion: APK_ANALYZER_VERSION,
    });
  }

  if (apk.suspiciousPermissions.length > 0) {
    indicators.push({
      category: 'APK_SUSPICIOUS_PERMISSIONS',
      severity: apk.suspiciousPermissions.length >= 3 ? 'HIGH' : 'MEDIUM',
      description: `Requests ${apk.suspiciousPermissions.length} permission(s) frequently associated with malware: ${apk.suspiciousPermissions.join(', ')}.`,
      confidence: 'MEDIUM',
      source: 'ApkAnalyzer',
      analyzerVersion: APK_ANALYZER_VERSION,
    });
  }

  if (!apk.signing.hasV1JarSigning && !apk.signing.hasV2SigningBlock) {
    indicators.push({
      category: 'APK_UNSIGNED',
      severity: 'HIGH',
      description: 'No JAR (v1) signing files or APK Signing Block (v2/v3) were found — the package does not appear to be signed.',
      confidence: 'MEDIUM',
      source: 'ApkAnalyzer',
      analyzerVersion: APK_ANALYZER_VERSION,
    });
  }

  if (!apk.hasClassesDex) {
    indicators.push({
      category: 'APK_MISSING_DEX',
      severity: 'LOW',
      description: 'No classes.dex was found in the package, which is unusual for a standard executable APK.',
      confidence: 'LOW',
      source: 'ApkAnalyzer',
      analyzerVersion: APK_ANALYZER_VERSION,
    });
  }

  if (apk.embeddedUrls.length > 0) {
    indicators.push({
      category: 'APK_EMBEDDED_URLS',
      severity: 'LOW',
      description: `Manifest string pool contains ${apk.embeddedUrls.length} embedded URL(s).`,
      confidence: 'LOW',
      source: 'ApkAnalyzer',
      analyzerVersion: APK_ANALYZER_VERSION,
    });
  }

  const exportedWithoutProtection = [...apk.activities, ...apk.services, ...apk.receivers, ...apk.providers]
    .filter((c) => c.exported === true);
  if (exportedWithoutProtection.length > 0) {
    indicators.push({
      category: 'APK_EXPORTED_COMPONENTS',
      severity: 'LOW',
      description: `${exportedWithoutProtection.length} component(s) are explicitly exported (accessible to other apps): ${exportedWithoutProtection.map((c) => c.name).slice(0, 5).join(', ')}.`,
      confidence: 'LOW',
      source: 'ApkAnalyzer',
      analyzerVersion: APK_ANALYZER_VERSION,
    });
  }

  return indicators;
}
