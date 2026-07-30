CREATE TABLE "PostureSnapshot" (
    "id" TEXT NOT NULL,
    "snapshotDate" TIMESTAMP(3) NOT NULL,
    "toxicIdentities" INTEGER NOT NULL,
    "totalConflicts" INTEGER NOT NULL,
    "criticalConflicts" INTEGER NOT NULL,
    "newConflicts" INTEGER NOT NULL,
    "remediatedConflicts" INTEGER NOT NULL,
    "attackPaths" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "PostureSnapshot_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "PostureSnapshot_snapshotDate_key"
ON "PostureSnapshot"("snapshotDate");

CREATE INDEX "PostureSnapshot_snapshotDate_idx"
ON "PostureSnapshot"("snapshotDate");
