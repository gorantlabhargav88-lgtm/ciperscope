import { sha256Hex } from './CanonicalHash';

export type MerkleProofStep = { hash: string; position: 'left' | 'right' };

/**
 * Deterministic SHA-256 Merkle tree over an already-ordered list of leaf
 * hashes (hex strings). Leaf ORDER is the caller's responsibility and part
 * of the deterministic contract — this module never sorts or reorders
 * input, so callers must always select leaves with an explicit ORDER BY
 * (never rely on implicit DB row order).
 *
 * Odd-node rule: at any level with an odd number of nodes, the last node
 * is duplicated and paired with itself to compute the parent — the same
 * convention used by Bitcoin's Merkle tree. This is documented explicitly
 * because the alternative (promoting the odd node unchanged to the next
 * level) produces a different, incompatible root for the same leaf set.
 */

function parentHash(left: string, right: string): string {
  return sha256Hex(left + right);
}

/** Returns null for an empty input — there is no meaningful root for zero
 *  evidence, and callers must treat that as its own explicit state rather
 *  than a valid (fabricated) root. */
export function buildMerkleRoot(leaves: string[]): string | null {
  if (leaves.length === 0) return null;
  if (leaves.length === 1) return leaves[0];

  let level = leaves;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i]; // odd-node duplication rule
      next.push(parentHash(left, right));
    }
    level = next;
  }
  return level[0];
}

/**
 * Sibling-path proof for the leaf at `index`, from leaf level up to (but
 * not including) the root. Verify by folding: start with the leaf hash,
 * then for each step compute parentHash(acc, step.hash) or
 * parentHash(step.hash, acc) depending on `position`, and compare the
 * final value to the known root.
 */
export function buildMerkleProof(leaves: string[], index: number): MerkleProofStep[] {
  if (index < 0 || index >= leaves.length) {
    throw new Error(`buildMerkleProof: index ${index} out of range for ${leaves.length} leaves`);
  }
  const proof: MerkleProofStep[] = [];
  let level = leaves;
  let i = index;
  while (level.length > 1) {
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) {
      const left = level[j];
      const right = j + 1 < level.length ? level[j + 1] : level[j];
      if (j === i || j + 1 === i) {
        const isLeft = i === j;
        proof.push({ hash: isLeft ? right : left, position: isLeft ? 'right' : 'left' });
      }
      next.push(parentHash(left, right));
    }
    i = Math.floor(i / 2);
    level = next;
  }
  return proof;
}

/** Recomputes the root from a leaf hash and its proof — for verification. */
export function verifyMerkleProof(leafHash: string, proof: MerkleProofStep[], expectedRoot: string): boolean {
  let acc = leafHash;
  for (const step of proof) {
    acc = step.position === 'left' ? parentHash(step.hash, acc) : parentHash(acc, step.hash);
  }
  return acc === expectedRoot;
}
