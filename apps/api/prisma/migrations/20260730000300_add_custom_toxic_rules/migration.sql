CREATE TABLE "CustomToxicRule" (
    "id" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "businessImpact" TEXT NOT NULL,
    "remediation" TEXT NOT NULL,
    "requirements" JSONB NOT NULL,
    "identityTypes" TEXT[],
    "minimumPlatforms" INTEGER,
    "mappings" JSONB NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'DRAFT',
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdBy" TEXT NOT NULL DEFAULT 'Customer security administrator',
    "publishedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CustomToxicRule_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "CustomToxicRule_ruleId_key" ON "CustomToxicRule"("ruleId");
CREATE INDEX "CustomToxicRule_status_idx" ON "CustomToxicRule"("status");
CREATE INDEX "CustomToxicRule_category_idx" ON "CustomToxicRule"("category");
