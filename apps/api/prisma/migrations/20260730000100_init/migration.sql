CREATE SCHEMA IF NOT EXISTS "public";

CREATE TYPE "IdentityType" AS ENUM ('HUMAN', 'SERVICE_ACCOUNT', 'WORKLOAD');
CREATE TYPE "Severity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

CREATE TABLE "Identity" (
    "id" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "displayName" TEXT NOT NULL,
    "email" TEXT,
    "type" "IdentityType" NOT NULL,
    "provider" TEXT NOT NULL,
    "department" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "blastRadius" JSONB NOT NULL,
    "attackPath" TEXT[],
    "lastActiveAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "Identity_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Grant" (
    "id" TEXT NOT NULL,
    "identityId" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "permission" TEXT NOT NULL,
    "resource" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Grant_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "RiskRule" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "description" TEXT NOT NULL,
    "businessImpact" TEXT NOT NULL,
    "remediation" TEXT NOT NULL,
    "mitreMappings" TEXT[],
    "nistMappings" TEXT[],
    "matching" JSONB NOT NULL,
    "riskWeight" INTEGER NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    CONSTRAINT "RiskRule_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "identityId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "confidence" DOUBLE PRECISION NOT NULL,
    "evidence" JSONB NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "detectedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "Identity_riskScore_idx" ON "Identity"("riskScore");
CREATE UNIQUE INDEX "Identity_provider_externalId_key" ON "Identity"("provider", "externalId");
CREATE INDEX "Grant_identityId_platform_idx" ON "Grant"("identityId", "platform");
CREATE INDEX "Finding_identityId_severity_idx" ON "Finding"("identityId", "severity");
CREATE UNIQUE INDEX "Finding_identityId_ruleId_key" ON "Finding"("identityId", "ruleId");

ALTER TABLE "Grant"
ADD CONSTRAINT "Grant_identityId_fkey"
FOREIGN KEY ("identityId") REFERENCES "Identity"("id")
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "Finding"
ADD CONSTRAINT "Finding_identityId_fkey"
FOREIGN KEY ("identityId") REFERENCES "Identity"("id")
ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "Finding"
ADD CONSTRAINT "Finding_ruleId_fkey"
FOREIGN KEY ("ruleId") REFERENCES "RiskRule"("id")
ON DELETE RESTRICT ON UPDATE CASCADE;
