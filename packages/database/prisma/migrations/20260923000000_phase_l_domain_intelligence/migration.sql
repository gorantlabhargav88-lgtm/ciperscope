-- Phase L: RDAP domain intelligence — global (not tenant-scoped, same
-- rationale as GeoLocation), keyed by registrable domain.
CREATE TYPE "RdapLookupStatus" AS ENUM ('SUCCESS', 'NOT_FOUND', 'PRIVATE_OR_RESERVED', 'MALFORMED_DOMAIN', 'PROVIDER_TIMEOUT', 'PROVIDER_ERROR', 'NOT_CONFIGURED');

-- CreateTable
CREATE TABLE "DomainIntelligence" (
    "id" TEXT NOT NULL,
    "registrableDomain" TEXT NOT NULL,
    "registrar" TEXT,
    "registrationDate" TIMESTAMP(3),
    "expirationDate" TIMESTAMP(3),
    "nameservers" JSONB,
    "domainStatus" JSONB,
    "rdapSource" TEXT,
    "status" "RdapLookupStatus" NOT NULL DEFAULT 'NOT_CONFIGURED',
    "errorMessage" TEXT,
    "fetchedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DomainIntelligence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DomainIntelligence_registrableDomain_key" ON "DomainIntelligence"("registrableDomain");

-- CreateIndex
CREATE INDEX "DomainIntelligence_status_idx" ON "DomainIntelligence"("status");
