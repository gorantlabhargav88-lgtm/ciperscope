/**
 * Application-facing Email contracts for the Email Forensics vertical slice.
 * These are hand-written API contracts, not a copy of the Prisma models in
 * packages/database/prisma/schema.prisma — they only include the fields the
 * existing services/api/src/modules/email/email.routes.ts endpoints actually
 * return today.
 */

export type EmailClassification =
  | 'UNKNOWN'
  | 'LEGITIMATE'
  | 'SUSPICIOUS'
  | 'PHISHING'
  | 'IMPERSONATION'
  | 'BEC'
  | 'FRAUD'
  | 'MALWARE';

export type AnalysisState = 'PENDING' | 'PROCESSING' | 'COMPLETED' | 'PARTIAL' | 'FAILED';

/** GET /emails/:emailId/headers -> { headers: EmailHeader[] } */
export interface EmailHeader {
  name: string;
  value: string;
  index: number;
}

/** GET /emails/:emailId/received-hops -> { hops: EmailRelayHop[] } */
export interface EmailRelayHop {
  hopOrder: number;
  sourceIp: string | null;
  hostname: string | null;
  receivedHeader: string;
  timestamp: string | null;
}

/** GET /emails/:emailId/mime-parts -> { mimeParts: EmailMimePart[] } */
export interface EmailMimePart {
  partIndex: string;
  contentType: string;
  filename: string | null;
  sizeBytes: number | null;
  isAttachment: boolean;
}

/** GET /emails/:emailId/urls -> { urls: EmailUrlEntry[] } */
export interface EmailUrlEntry {
  url: string;
  domain: string | null;
  normalizedUrl: string | null;
  isObfuscated: boolean;
  indicators: string[] | null;
  source: string;
}

export interface ArchiveMetadata {
  entryCount?: number;
  totalUncompressedSize?: number;
  hasTraversal?: boolean;
  hasNestedArchive?: boolean;
  error?: string;
}

export type AttachmentThreatSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface AttachmentThreatIndicatorEntry {
  category: string;
  severity: AttachmentThreatSeverity;
  description: string;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  source: string;
  analyzerVersion: string;
}

export interface ApkComponentEntry {
  name: string;
  exported: boolean | null;
}

/** Populated only when an attachment was identified as an Android APK
 *  (via AndroidManifest.xml presence, never filename/extension alone). */
export interface ApkMetadataEntry {
  packageName: string | null;
  versionCode: string | null;
  versionName: string | null;
  minSdkVersion: string | null;
  targetSdkVersion: string | null;
  permissions: string[];
  suspiciousPermissions: string[];
  activities: ApkComponentEntry[];
  services: ApkComponentEntry[];
  receivers: ApkComponentEntry[];
  providers: ApkComponentEntry[];
  embeddedUrls: string[];
  hasClassesDex: boolean;
  nativeLibraries: string[];
  signing: {
    hasV1JarSigning: boolean;
    hasV2SigningBlock: boolean;
    signingFiles: string[];
  };
  manifestParseError: string | null;
  analyzerVersion: string;
}

export type QrPayloadType = 'URL' | 'TEXT' | 'OTHER';

export interface QrCodeEntry {
  payload: string;
  type: QrPayloadType;
}

/** Populated only when an attachment was identified as an image and QR
 *  code(s) were decoded from it. Decoded URLs are also persisted as
 *  ordinary EmailUrl rows (source QR_CODE) — this is the raw decode
 *  record, not a second source of truth for URL analysis. */
export interface QrFindingsEntry {
  detected: boolean;
  codes: QrCodeEntry[];
  errors?: string[];
}

/** GET /emails/:emailId/attachments -> { attachments: EmailAttachmentEntry[] } */
export interface EmailAttachmentEntry {
  id: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string | null;
  actualMimeType: string | null;
  isMismatch: boolean;
  isArchive: boolean;
  magicBytes: string | null;
  archiveMetadata: ArchiveMetadata | null;
  threatIndicators?: AttachmentThreatIndicatorEntry[] | null;
  apkMetadata?: ApkMetadataEntry | null;
  qrFindings?: QrFindingsEntry | null;
}

/**
 * GET /emails/:emailId/analysis response.
 * `caseId` is `null` when the email has not been linked to a case yet
 * (Email.caseId is nullable in the schema) — this is a real, honest state,
 * not a missing-data placeholder.
 */
export interface EmailAnalysisSummary {
  id: string;
  caseId: string | null;
  analysisStatus: AnalysisState;
  classification: EmailClassification | null;
  riskScore: number | null;
  createdAt: string;
  riskAssessment: EmailRiskAssessment | null;
}

export interface EmailRiskFactor {
  category: string;
  description: string;
  scoreContribution: number;
}

export interface EmailRiskAssessment {
  overallScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  version: string;
  factors: EmailRiskFactor[];
}

// Phase I — GET /emails/:emailId/evidence-graph
export type EvidenceGraphNodeType =
  | 'EMAIL' | 'DOMAIN' | 'URL' | 'IP' | 'ATTACHMENT' | 'FILE_HASH'
  | 'QR_CODE' | 'APK' | 'CTI_INDICATOR' | 'GEOLOCATION' | 'THREAT_INDICATOR';

export type EvidenceGraphEdgeType =
  | 'CONTAINS_URL' | 'HAS_ATTACHMENT' | 'RECEIVED_FROM_IP' | 'BELONGS_TO_DOMAIN'
  | 'HAS_HASH' | 'CONTAINS_QR' | 'DECODED_TO_URL' | 'IS_APK'
  | 'OBSERVED_BY_CTI' | 'HAS_GEOLOCATION' | 'HAS_INDICATOR';

export interface EvidenceGraphProvenanceEntry {
  source: string;
  sourceRecordId?: string;
  confidence?: number | null;
  createdAt?: string;
}

export interface EvidenceGraphNode {
  id: string;
  type: EvidenceGraphNodeType;
  label: string;
  organizationId: string;
  data: Record<string, unknown>;
  provenance: EvidenceGraphProvenanceEntry[];
}

export interface EvidenceGraphEdge {
  id: string;
  from: string;
  to: string;
  type: EvidenceGraphEdgeType;
  provenance: EvidenceGraphProvenanceEntry[];
}

export interface EvidenceGraphResponse {
  emailId: string;
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
  metadata: {
    generatedAt: string;
    nodeCount: number;
    edgeCount: number;
    truncated: boolean;
  };
}

// Phase J — POST/GET /emails/:emailId/reports, GET /reports/:reportId(/download)
export type ForensicReportStatus = 'QUEUED' | 'GENERATING' | 'COMPLETED' | 'FAILED';

export interface ForensicReport {
  id: string;
  organizationId: string;
  emailId: string;
  status: ForensicReportStatus;
  reportVersion: string;
  generatedAt: string | null;
  sha256: string | null;
  errorMessage: string | null;
  requestedById: string | null;
  createdAt: string;
  updatedAt: string;
}
