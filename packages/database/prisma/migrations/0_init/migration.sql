-- CreateEnum
CREATE TYPE "CaseStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "Priority" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "EmailClassification" AS ENUM ('UNKNOWN', 'LEGITIMATE', 'SUSPICIOUS', 'PHISHING', 'IMPERSONATION', 'BEC', 'FRAUD', 'MALWARE');

-- CreateEnum
CREATE TYPE "AuthResultStatus" AS ENUM ('PASS', 'FAIL', 'SOFTFAIL', 'NEUTRAL', 'NONE', 'TEMPERROR', 'PERMERROR');

-- CreateEnum
CREATE TYPE "IndicatorType" AS ENUM ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL_ADDRESS', 'ASN');

-- CreateEnum
CREATE TYPE "ThreatVerdict" AS ENUM ('CLEAN', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN');

-- CreateEnum
CREATE TYPE "EvidenceType" AS ENUM ('RAW_EMAIL', 'HEADER', 'ATTACHMENT', 'URL', 'IP', 'DOMAIN', 'SCREENSHOT', 'REPORT', 'LOG', 'OTHER');

-- CreateEnum
CREATE TYPE "EvidenceStatus" AS ENUM ('ACTIVE', 'ARCHIVED', 'DELETED');

-- CreateEnum
CREATE TYPE "CustodyAction" AS ENUM ('COLLECTED', 'UPLOADED', 'HASHED', 'ANALYZED', 'EXPORTED', 'VERIFIED', 'BLOCKCHAIN_ANCHORED', 'ACCESSED');

-- CreateEnum
CREATE TYPE "BlockchainAnchorStatus" AS ENUM ('PENDING', 'SUBMITTED', 'CONFIRMED', 'FAILED', 'VERIFICATION_FAILED');

-- CreateEnum
CREATE TYPE "AlertSeverity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "IdempotencyOperationStatus" AS ENUM ('PENDING', 'PROCESSING', 'SUCCEEDED', 'FAILED', 'RECONCILIATION_REQUIRED');

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "domain" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "firstName" TEXT,
    "lastName" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "lastLoginAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrganizationMember" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "roleId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "OrganizationMember_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Role" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "isSystem" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Role_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Permission" (
    "id" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Permission_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RolePermission" (
    "roleId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,

    CONSTRAINT "RolePermission_pkey" PRIMARY KEY ("roleId","permissionId")
);

-- CreateTable
CREATE TABLE "Session" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "deviceId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "isValid" BOOLEAN NOT NULL DEFAULT true,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "Session_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RefreshToken" (
    "id" TEXT NOT NULL,
    "sessionId" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "isRevoked" BOOLEAN NOT NULL DEFAULT false,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "VerificationToken" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "VerificationToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "APIKey" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "prefix" TEXT NOT NULL,
    "hash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3),
    "lastUsedAt" TIMESTAMP(3),
    "isRevoked" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "APIKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Case" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" "Priority" NOT NULL DEFAULT 'LOW',
    "priority" "Priority" NOT NULL DEFAULT 'LOW',
    "status" "CaseStatus" NOT NULL DEFAULT 'OPEN',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Case_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Investigation" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Investigation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "InvestigationNote" (
    "id" TEXT NOT NULL,
    "investigationId" TEXT NOT NULL,
    "content" TEXT NOT NULL,
    "authorId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InvestigationNote_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Email" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "caseId" TEXT,
    "messageId" TEXT,
    "subject" TEXT,
    "senderAddress" TEXT,
    "replyTo" TEXT,
    "returnPath" TEXT,
    "date" TIMESTAMP(3),
    "ingestionSrc" TEXT NOT NULL DEFAULT 'UPLOAD',
    "rawStorageKey" TEXT,
    "sha256" TEXT NOT NULL,
    "classification" "EmailClassification" NOT NULL DEFAULT 'UNKNOWN',
    "riskScore" DOUBLE PRECISION,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Email_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailHeader" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailHeader_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RelayHop" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "hopOrder" INTEGER NOT NULL,
    "sourceIp" TEXT,
    "hostname" TEXT,
    "timestamp" TIMESTAMP(3),
    "receivedHeader" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RelayHop_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailAttachment" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "filename" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "sha256" TEXT,
    "storageKey" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailAttachment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailUrl" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "domain" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailUrl_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthenticationResult" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "spf" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "dkim" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "dmarc" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "details" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthenticationResult_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Indicator" (
    "id" TEXT NOT NULL,
    "type" "IndicatorType" NOT NULL,
    "value" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Indicator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ThreatIntelObservation" (
    "id" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "verdict" "ThreatVerdict" NOT NULL,
    "confidence" DOUBLE PRECISION,
    "rawResponse" JSONB,
    "observationTime" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ThreatIntelObservation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GeoLocation" (
    "id" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "country" TEXT,
    "region" TEXT,
    "city" TEXT,
    "latitude" DOUBLE PRECISION,
    "longitude" DOUBLE PRECISION,
    "asn" TEXT,
    "isp" TEXT,
    "provider" TEXT NOT NULL DEFAULT 'MaxMind',
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "GeoLocation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "MLInference" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "modelIdentifier" TEXT NOT NULL,
    "prediction" TEXT NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "processingTimeMs" INTEGER,
    "explanation" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "MLInference_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskAssessment" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "overallScore" DOUBLE PRECISION NOT NULL,
    "riskLevel" "Priority" NOT NULL,
    "version" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskAssessment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RiskFactor" (
    "id" TEXT NOT NULL,
    "riskAssessmentId" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "scoreContribution" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RiskFactor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Campaign" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "firstSeen" TIMESTAMP(3) NOT NULL,
    "lastSeen" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Campaign_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CampaignIndicator" (
    "campaignId" TEXT NOT NULL,
    "indicatorId" TEXT NOT NULL,

    CONSTRAINT "CampaignIndicator_pkey" PRIMARY KEY ("campaignId","indicatorId")
);

-- CreateTable
CREATE TABLE "CampaignEmail" (
    "campaignId" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,

    CONSTRAINT "CampaignEmail_pkey" PRIMARY KEY ("campaignId","emailId")
);

-- CreateTable
CREATE TABLE "Evidence" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "type" "EvidenceType" NOT NULL,
    "storageKey" TEXT NOT NULL,
    "filename" TEXT,
    "mimeType" TEXT,
    "sizeBytes" INTEGER,
    "sha256" TEXT NOT NULL,
    "status" "EvidenceStatus" NOT NULL DEFAULT 'ACTIVE',
    "collectionTime" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "collectedById" TEXT,

    CONSTRAINT "Evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ChainOfCustodyEvent" (
    "id" TEXT NOT NULL,
    "evidenceId" TEXT NOT NULL,
    "action" "CustodyAction" NOT NULL,
    "actorId" TEXT,
    "description" TEXT,
    "previousEventId" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ChainOfCustodyEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlockchainAnchor" (
    "id" TEXT NOT NULL,
    "evidenceId" TEXT NOT NULL,
    "network" TEXT NOT NULL DEFAULT 'HyperledgerFabric',
    "transactionId" TEXT,
    "blockNumber" INTEGER,
    "status" "BlockchainAnchorStatus" NOT NULL DEFAULT 'PENDING',
    "errorDetails" TEXT,
    "anchorTimestamp" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "BlockchainAnchor_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Alert" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "caseId" TEXT,
    "title" TEXT NOT NULL,
    "message" TEXT NOT NULL,
    "severity" "AlertSeverity" NOT NULL DEFAULT 'INFO',
    "isRead" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Alert_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "contentHtml" TEXT,
    "storageKey" TEXT,
    "generatedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT,
    "actorId" TEXT,
    "action" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "resourceId" TEXT,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SystemSetting" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SystemSetting_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "IdempotencyOperation" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "operationKey" TEXT NOT NULL,
    "operationType" TEXT NOT NULL,
    "resourceId" TEXT,
    "status" "IdempotencyOperationStatus" NOT NULL DEFAULT 'PENDING',
    "resultReference" TEXT,
    "errorCode" TEXT,
    "errorMessage" TEXT,
    "attemptCount" INTEGER NOT NULL DEFAULT 0,
    "lockedUntil" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "IdempotencyOperation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Organization_domain_key" ON "Organization"("domain");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "OrganizationMember_organizationId_idx" ON "OrganizationMember"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "OrganizationMember_userId_organizationId_key" ON "OrganizationMember"("userId", "organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Role_organizationId_name_key" ON "Role"("organizationId", "name");

-- CreateIndex
CREATE UNIQUE INDEX "Permission_action_key" ON "Permission"("action");

-- CreateIndex
CREATE UNIQUE INDEX "RefreshToken_tokenHash_key" ON "RefreshToken"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "VerificationToken_tokenHash_key" ON "VerificationToken"("tokenHash");

-- CreateIndex
CREATE INDEX "VerificationToken_email_type_idx" ON "VerificationToken"("email", "type");

-- CreateIndex
CREATE UNIQUE INDEX "APIKey_hash_key" ON "APIKey"("hash");

-- CreateIndex
CREATE INDEX "APIKey_organizationId_idx" ON "APIKey"("organizationId");

-- CreateIndex
CREATE INDEX "Case_organizationId_idx" ON "Case"("organizationId");

-- CreateIndex
CREATE INDEX "Case_status_priority_idx" ON "Case"("status", "priority");

-- CreateIndex
CREATE INDEX "Email_organizationId_idx" ON "Email"("organizationId");

-- CreateIndex
CREATE INDEX "Email_messageId_idx" ON "Email"("messageId");

-- CreateIndex
CREATE INDEX "Email_senderAddress_idx" ON "Email"("senderAddress");

-- CreateIndex
CREATE INDEX "Email_caseId_idx" ON "Email"("caseId");

-- CreateIndex
CREATE UNIQUE INDEX "Email_organizationId_sha256_key" ON "Email"("organizationId", "sha256");

-- CreateIndex
CREATE INDEX "EmailHeader_emailId_idx" ON "EmailHeader"("emailId");

-- CreateIndex
CREATE INDEX "RelayHop_emailId_idx" ON "RelayHop"("emailId");

-- CreateIndex
CREATE INDEX "EmailAttachment_emailId_idx" ON "EmailAttachment"("emailId");

-- CreateIndex
CREATE INDEX "EmailUrl_emailId_idx" ON "EmailUrl"("emailId");

-- CreateIndex
CREATE UNIQUE INDEX "AuthenticationResult_emailId_key" ON "AuthenticationResult"("emailId");

-- CreateIndex
CREATE UNIQUE INDEX "Indicator_value_key" ON "Indicator"("value");

-- CreateIndex
CREATE INDEX "Indicator_type_value_idx" ON "Indicator"("type", "value");

-- CreateIndex
CREATE INDEX "ThreatIntelObservation_indicatorId_idx" ON "ThreatIntelObservation"("indicatorId");

-- CreateIndex
CREATE INDEX "ThreatIntelObservation_provider_idx" ON "ThreatIntelObservation"("provider");

-- CreateIndex
CREATE UNIQUE INDEX "GeoLocation_ipAddress_key" ON "GeoLocation"("ipAddress");

-- CreateIndex
CREATE INDEX "MLInference_emailId_idx" ON "MLInference"("emailId");

-- CreateIndex
CREATE INDEX "RiskAssessment_emailId_idx" ON "RiskAssessment"("emailId");

-- CreateIndex
CREATE UNIQUE INDEX "Evidence_sha256_key" ON "Evidence"("sha256");

-- CreateIndex
CREATE INDEX "Evidence_caseId_idx" ON "Evidence"("caseId");

-- CreateIndex
CREATE UNIQUE INDEX "ChainOfCustodyEvent_previousEventId_key" ON "ChainOfCustodyEvent"("previousEventId");

-- CreateIndex
CREATE INDEX "ChainOfCustodyEvent_evidenceId_idx" ON "ChainOfCustodyEvent"("evidenceId");

-- CreateIndex
CREATE UNIQUE INDEX "BlockchainAnchor_evidenceId_key" ON "BlockchainAnchor"("evidenceId");

-- CreateIndex
CREATE UNIQUE INDEX "BlockchainAnchor_transactionId_key" ON "BlockchainAnchor"("transactionId");

-- CreateIndex
CREATE INDEX "BlockchainAnchor_status_idx" ON "BlockchainAnchor"("status");

-- CreateIndex
CREATE INDEX "Alert_organizationId_isRead_idx" ON "Alert"("organizationId", "isRead");

-- CreateIndex
CREATE INDEX "Report_caseId_idx" ON "Report"("caseId");

-- CreateIndex
CREATE INDEX "AuditLog_organizationId_idx" ON "AuditLog"("organizationId");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "SystemSetting_organizationId_key_key" ON "SystemSetting"("organizationId", "key");

-- CreateIndex
CREATE INDEX "IdempotencyOperation_organizationId_operationKey_idx" ON "IdempotencyOperation"("organizationId", "operationKey");

-- CreateIndex
CREATE UNIQUE INDEX "IdempotencyOperation_organizationId_operationKey_resourceId_key" ON "IdempotencyOperation"("organizationId", "operationKey", "resourceId");

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrganizationMember" ADD CONSTRAINT "OrganizationMember_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Role" ADD CONSTRAINT "Role_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_roleId_fkey" FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "Permission"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Session" ADD CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RefreshToken" ADD CONSTRAINT "RefreshToken_sessionId_fkey" FOREIGN KEY ("sessionId") REFERENCES "Session"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "APIKey" ADD CONSTRAINT "APIKey_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Case" ADD CONSTRAINT "Case_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Investigation" ADD CONSTRAINT "Investigation_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "InvestigationNote" ADD CONSTRAINT "InvestigationNote_investigationId_fkey" FOREIGN KEY ("investigationId") REFERENCES "Investigation"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailHeader" ADD CONSTRAINT "EmailHeader_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RelayHop" ADD CONSTRAINT "RelayHop_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailAttachment" ADD CONSTRAINT "EmailAttachment_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailUrl" ADD CONSTRAINT "EmailUrl_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthenticationResult" ADD CONSTRAINT "AuthenticationResult_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatIntelObservation" ADD CONSTRAINT "ThreatIntelObservation_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "Indicator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MLInference" ADD CONSTRAINT "MLInference_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskAssessment" ADD CONSTRAINT "RiskAssessment_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RiskFactor" ADD CONSTRAINT "RiskFactor_riskAssessmentId_fkey" FOREIGN KEY ("riskAssessmentId") REFERENCES "RiskAssessment"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignIndicator" ADD CONSTRAINT "CampaignIndicator_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignIndicator" ADD CONSTRAINT "CampaignIndicator_indicatorId_fkey" FOREIGN KEY ("indicatorId") REFERENCES "Indicator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignEmail" ADD CONSTRAINT "CampaignEmail_campaignId_fkey" FOREIGN KEY ("campaignId") REFERENCES "Campaign"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CampaignEmail" ADD CONSTRAINT "CampaignEmail_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Evidence" ADD CONSTRAINT "Evidence_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChainOfCustodyEvent" ADD CONSTRAINT "ChainOfCustodyEvent_evidenceId_fkey" FOREIGN KEY ("evidenceId") REFERENCES "Evidence"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChainOfCustodyEvent" ADD CONSTRAINT "ChainOfCustodyEvent_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ChainOfCustodyEvent" ADD CONSTRAINT "ChainOfCustodyEvent_previousEventId_fkey" FOREIGN KEY ("previousEventId") REFERENCES "ChainOfCustodyEvent"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlockchainAnchor" ADD CONSTRAINT "BlockchainAnchor_evidenceId_fkey" FOREIGN KEY ("evidenceId") REFERENCES "Evidence"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Alert" ADD CONSTRAINT "Alert_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Alert" ADD CONSTRAINT "Alert_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "Case"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SystemSetting" ADD CONSTRAINT "SystemSetting_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

