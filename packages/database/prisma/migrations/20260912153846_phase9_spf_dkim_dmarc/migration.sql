/*
  Warnings:

  - You are about to drop the `AuthenticationResult` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "AuthenticationResult" DROP CONSTRAINT "AuthenticationResult_emailId_fkey";

-- DropTable
DROP TABLE "AuthenticationResult";

-- CreateTable
CREATE TABLE "EmailAuthenticationAnalysis" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "spf" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "dkim" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "dmarc" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "isConsistent" BOOLEAN NOT NULL DEFAULT false,
    "summary" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmailAuthenticationAnalysis_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SpfVerification" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "result" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "domain" TEXT,
    "evaluatedIp" TEXT,
    "matchedMechanism" TEXT,
    "explanation" TEXT,
    "lookups" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SpfVerification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DkimVerification" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "result" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "domain" TEXT,
    "selector" TEXT,
    "algorithm" TEXT,
    "bodyHashResult" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "explanation" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DkimVerification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DmarcVerification" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "result" "AuthResultStatus" NOT NULL DEFAULT 'NONE',
    "orgDomain" TEXT,
    "policy" TEXT,
    "subdomainPolicy" TEXT,
    "spfAlignment" TEXT,
    "dkimAlignment" TEXT,
    "explanation" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DmarcVerification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DnsObservation" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "queryName" TEXT NOT NULL,
    "recordType" TEXT NOT NULL,
    "response" TEXT,
    "rcode" TEXT,
    "durationMs" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DnsObservation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EmailAuthenticationAnalysis_emailId_key" ON "EmailAuthenticationAnalysis"("emailId");

-- CreateIndex
CREATE INDEX "SpfVerification_emailId_idx" ON "SpfVerification"("emailId");

-- CreateIndex
CREATE INDEX "DkimVerification_emailId_idx" ON "DkimVerification"("emailId");

-- CreateIndex
CREATE UNIQUE INDEX "DmarcVerification_emailId_key" ON "DmarcVerification"("emailId");

-- CreateIndex
CREATE INDEX "DnsObservation_emailId_idx" ON "DnsObservation"("emailId");

-- AddForeignKey
ALTER TABLE "EmailAuthenticationAnalysis" ADD CONSTRAINT "EmailAuthenticationAnalysis_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SpfVerification" ADD CONSTRAINT "SpfVerification_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DkimVerification" ADD CONSTRAINT "DkimVerification_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DmarcVerification" ADD CONSTRAINT "DmarcVerification_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DnsObservation" ADD CONSTRAINT "DnsObservation_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;
