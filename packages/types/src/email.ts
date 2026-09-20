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
