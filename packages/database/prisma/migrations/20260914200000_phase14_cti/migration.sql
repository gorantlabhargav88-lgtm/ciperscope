-- CreateTable
CREATE TABLE "ThreatIndicator" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "iocType" "IndicatorType" NOT NULL,
    "iocValue" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "status" "ThreatVerdict" NOT NULL,
    "confidence" INTEGER,
    "metadata" JSONB,

    CONSTRAINT "ThreatIndicator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "GeolocationInfo" (
    "id" TEXT NOT NULL,
    "emailId" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "country" TEXT,
    "city" TEXT,
    "asn" TEXT,
    "isp" TEXT,

    CONSTRAINT "GeolocationInfo_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ThreatIndicator_emailId_idx" ON "ThreatIndicator"("emailId");

-- CreateIndex
CREATE UNIQUE INDEX "ThreatIndicator_emailId_iocValue_provider_key" ON "ThreatIndicator"("emailId", "iocValue", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "GeolocationInfo_emailId_ipAddress_key" ON "GeolocationInfo"("emailId", "ipAddress");

-- AddForeignKey
ALTER TABLE "ThreatIndicator" ADD CONSTRAINT "ThreatIndicator_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "GeolocationInfo" ADD CONSTRAINT "GeolocationInfo_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;
