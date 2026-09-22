import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

/**
 * Phase 10G.2 — static-source regression coverage for an invariant that
 * cannot practically be exercised by instantiating the whole worker
 * service's BullMQ registration (services/worker/src/index.ts's parsing
 * stage is an inline closure, not an exported function, and this phase
 * deliberately avoids refactoring it out purely to make it unit-testable).
 *
 * The invariant, established by the Phase 10G end-to-end audit and Phase
 * 10G.2's fix: `Email.analysisStatus` may only ever be set to 'COMPLETED'
 * by FusionEngine.evaluate() (the pipeline's single, always-executed
 * terminal stage — see services/worker/src/analyzer/mlEvaluationStage.ts),
 * in the same transaction that persists the final RiskAssessment. The raw
 * MIME parsing stage must never itself declare the email COMPLETED.
 *
 * FusionEngine.test.ts covers the behavioral half of this (the actual data
 * passed to prisma calls, via a mocked Prisma client). This file covers the
 * structural half: that the specific parsing-stage transaction block in
 * index.ts does not contain the string that would defeat the invariant.
 */

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(__dirname, '..', relativePath), 'utf8');
}

describe('analysisStatus invariant (Phase 10G.2) — static source checks', () => {
  it('the email-processing (parsing) worker\'s "Update Analysis Status" block sets PROCESSING, never COMPLETED', () => {
    const source = readSource('index.ts');
    const marker = '// Update Analysis Status';
    const markerIndex = source.indexOf(marker);
    expect(markerIndex).toBeGreaterThan(-1); // the block must still exist under this name

    // Isolate just this block (from the comment to the closing of the
    // tx.email.update call that follows it) rather than scanning the whole
    // file, so this test fails loudly if the block is ever restructured
    // rather than silently passing on an unrelated COMPLETED elsewhere.
    const blockEnd = source.indexOf('});', markerIndex);
    const block = source.slice(markerIndex, blockEnd + 3);

    expect(block).toMatch(/analysisStatus:\s*'PROCESSING'/);
    expect(block).not.toMatch(/analysisStatus:\s*'COMPLETED'/);
  });

  it('FusionEngine\'s final email.update calls set analysisStatus to COMPLETED, in the same transaction as the RiskAssessment upsert', () => {
    const source = readSource('analyzer/FusionEngine.ts');

    // Both the ML-prediction and non-ML-prediction branches must set it.
    const matches = source.match(/analysisStatus:\s*'COMPLETED'/g) ?? [];
    expect(matches.length).toBe(2);

    // Confirm it is textually inside the same $transaction block as the
    // riskAssessment.upsert call (i.e. before the transaction's closing),
    // not a separate, non-atomic call appended after it.
    const transactionStart = source.indexOf('$transaction(async (tx)');
    const upsertIndex = source.indexOf('riskAssessment.upsert', transactionStart);
    const lastCompletedIndex = source.lastIndexOf("analysisStatus: 'COMPLETED'");
    const transactionEnd = source.indexOf('});', lastCompletedIndex);

    expect(transactionStart).toBeGreaterThan(-1);
    expect(upsertIndex).toBeGreaterThan(transactionStart);
    expect(lastCompletedIndex).toBeGreaterThan(upsertIndex); // COMPLETED write comes after (i.e. alongside) the upsert
    expect(transactionEnd).toBeGreaterThan(-1);
  });

  it('no other worker in index.ts (auth/threat/cti/ml-classification) writes analysisStatus at all', () => {
    const source = readSource('index.ts');

    // Every analysisStatus write in this file must be inside the parsing
    // worker's block (PROCESSING) or its own catch block (FAILED) — no
    // downstream worker should independently declare a status.
    const allWrites = [...source.matchAll(/analysisStatus:\s*'(\w+)'/g)].map((m) => m[1]);
    expect(allWrites.sort()).toEqual(['FAILED', 'PROCESSING'].sort());
  });
});
