import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import '@ciperscope/config';
import crypto from 'crypto';
import { prisma } from '@ciperscope/database';
import { computeEvidenceHash, buildMerkleRoot } from '@ciperscope/integrity';
import { runNotarizationBatch } from '../EvidenceBatchingService';
import { NullBlockchainAnchorProvider } from '../providers/NullBlockchainAnchorProvider';
import { IBlockchainAnchorProvider, AnchorOutcome } from '../providers/IBlockchainAnchorProvider';

/** A provider that counts calls, for concurrency assertions. */
class CountingNullProvider implements IBlockchainAnchorProvider {
  public readonly name = 'counting-null';
  public calls = 0;
  async anchorMerkleRoot(): Promise<AnchorOutcome> {
    this.calls += 1;
    return { status: 'NOT_CONFIGURED' };
  }
  async getAnchorStatus(): Promise<AnchorOutcome> {
    return { status: 'NOT_CONFIGURED' };
  }
}

describe('EvidenceBatchingService (Integration, real Postgres)', () => {
  let orgA: string;
  let orgB: string;
  let caseA: string;
  let caseB: string;

  beforeAll(async () => {
    orgA = crypto.randomUUID();
    orgB = crypto.randomUUID();
    await prisma.organization.createMany({ data: [{ id: orgA, name: 'Batching Test Org A' }, { id: orgB, name: 'Batching Test Org B' }] });
    const a = await prisma.case.create({ data: { organizationId: orgA, title: 'Batching Case A' } });
    const b = await prisma.case.create({ data: { organizationId: orgB, title: 'Batching Case B' } });
    caseA = a.id;
    caseB = b.id;
  });

  afterAll(async () => {
    await prisma.evidence.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.blockchainAnchor.deleteMany({ where: { organizationId: { in: [orgA, orgB] } } });
    await prisma.case.deleteMany({ where: { id: { in: [caseA, caseB] } } });
    await prisma.organization.deleteMany({ where: { id: { in: [orgA, orgB] } } });
  });

  async function makeEvidence(organizationId: string, caseId: string, n: number) {
    const rows = [];
    for (let i = 0; i < n; i++) {
      rows.push(
        await prisma.evidence.create({
          data: { organizationId, caseId, type: 'LOG', storageKey: `k-${crypto.randomUUID()}`, sha256: crypto.randomBytes(32).toString('hex'), status: 'ACTIVE' },
        })
      );
    }
    return rows;
  }

  it('batches eligible ACTIVE evidence into a BlockchainAnchor with a real, reconstructible Merkle root', async () => {
    const rows = await makeEvidence(orgA, caseA, 3);
    const provider = new NullBlockchainAnchorProvider();

    const anchor = await runNotarizationBatch(prisma, orgA, provider);
    expect(anchor).not.toBeNull();
    expect(anchor!.evidenceCount).toBe(3);
    expect(anchor!.status).toBe('NOT_CONFIGURED'); // no real blockchain configured

    const expectedHashes = rows
      .slice()
      .sort((a, b) => a.collectionTime.getTime() - b.collectionTime.getTime() || a.id.localeCompare(b.id))
      .map((e) => computeEvidenceHash({ id: e.id, organizationId: e.organizationId, caseId: e.caseId, type: e.type, sha256: e.sha256, filename: e.filename, mimeType: e.mimeType, sizeBytes: e.sizeBytes, collectionTime: e.collectionTime }));
    expect(buildMerkleRoot(expectedHashes)).toBe(anchor!.merkleRoot);

    // Every batched evidence row is now claimed.
    const claimed = await prisma.evidence.findMany({ where: { id: { in: rows.map((r) => r.id) } } });
    expect(claimed.every((e) => e.anchorId === anchor!.id)).toBe(true);
  });

  it('never double-anchors: a second run for the same org with no new evidence is a no-op', async () => {
    const provider = new NullBlockchainAnchorProvider();
    const before = await prisma.blockchainAnchor.count({ where: { organizationId: orgA } });
    const anchor = await runNotarizationBatch(prisma, orgA, provider);
    expect(anchor).toBeNull(); // nothing new eligible
    const after = await prisma.blockchainAnchor.count({ where: { organizationId: orgA } });
    expect(after).toBe(before);
  });

  it('a new evidence item added later forms its own separate batch — never mixed into the already-anchored batch', async () => {
    const [newEvidence] = await makeEvidence(orgA, caseA, 1);
    const provider = new NullBlockchainAnchorProvider();
    const anchor = await runNotarizationBatch(prisma, orgA, provider);
    expect(anchor).not.toBeNull();
    expect(anchor!.evidenceCount).toBe(1);
    const claimed = await prisma.evidence.findUniqueOrThrow({ where: { id: newEvidence.id } });
    expect(claimed.anchorId).toBe(anchor!.id);
  });

  it('tenant isolation — a batch for orgA never includes orgB\'s evidence, even with overlapping timestamps', async () => {
    await makeEvidence(orgB, caseB, 2);
    const provider = new NullBlockchainAnchorProvider();
    const anchor = await runNotarizationBatch(prisma, orgB, provider);
    expect(anchor).not.toBeNull();
    expect(anchor!.organizationId).toBe(orgB);
    const ids = anchor!.evidenceIds as string[];
    const rows = await prisma.evidence.findMany({ where: { id: { in: ids } } });
    expect(rows.every((r) => r.organizationId === orgB)).toBe(true);
  });

  it('concurrent runs for the same organization never duplicate an anchor for the same evidence set', async () => {
    const orgC = crypto.randomUUID();
    await prisma.organization.create({ data: { id: orgC, name: 'Batching Test Org C' } });
    const caseC = await prisma.case.create({ data: { organizationId: orgC, title: 'Batching Case C' } });
    await makeEvidence(orgC, caseC.id, 4);

    const provider = new CountingNullProvider();
    const results = await Promise.all([
      runNotarizationBatch(prisma, orgC, provider),
      runNotarizationBatch(prisma, orgC, provider),
      runNotarizationBatch(prisma, orgC, provider),
    ]);

    const anchors = results.filter((r): r is NonNullable<typeof r> => r !== null);
    const uniqueAnchorIds = new Set(anchors.map((a) => a.id));
    expect(uniqueAnchorIds.size).toBe(1); // all concurrent calls converge on the same single anchor

    const totalAnchors = await prisma.blockchainAnchor.count({ where: { organizationId: orgC } });
    expect(totalAnchors).toBe(1);

    await prisma.evidence.deleteMany({ where: { organizationId: orgC } });
    await prisma.blockchainAnchor.deleteMany({ where: { organizationId: orgC } });
    await prisma.case.deleteMany({ where: { id: caseC.id } });
    await prisma.organization.deleteMany({ where: { id: orgC } });
  });

  it('a batch with soft-deleted (status: DELETED) evidence never includes it', async () => {
    const orgD = crypto.randomUUID();
    await prisma.organization.create({ data: { id: orgD, name: 'Batching Test Org D' } });
    const caseD = await prisma.case.create({ data: { organizationId: orgD, title: 'Batching Case D' } });
    const [active, deleted] = await Promise.all([
      prisma.evidence.create({ data: { organizationId: orgD, caseId: caseD.id, type: 'LOG', storageKey: 'k1', sha256: crypto.randomBytes(32).toString('hex'), status: 'ACTIVE' } }),
      prisma.evidence.create({ data: { organizationId: orgD, caseId: caseD.id, type: 'LOG', storageKey: 'k2', sha256: crypto.randomBytes(32).toString('hex'), status: 'DELETED' } }),
    ]);

    const provider = new NullBlockchainAnchorProvider();
    const anchor = await runNotarizationBatch(prisma, orgD, provider);
    expect(anchor!.evidenceCount).toBe(1);
    expect((anchor!.evidenceIds as string[])).toEqual([active.id]);
    expect((anchor!.evidenceIds as string[])).not.toContain(deleted.id);

    await prisma.evidence.deleteMany({ where: { organizationId: orgD } });
    await prisma.blockchainAnchor.deleteMany({ where: { organizationId: orgD } });
    await prisma.case.deleteMany({ where: { id: caseD.id } });
    await prisma.organization.deleteMany({ where: { id: orgD } });
  });
});
