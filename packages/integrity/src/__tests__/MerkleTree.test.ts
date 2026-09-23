import { describe, it, expect } from 'vitest';
import { buildMerkleRoot, buildMerkleProof, verifyMerkleProof } from '../MerkleTree';
import { sha256Hex } from '../CanonicalHash';

const L = (n: number) => Array.from({ length: n }, (_, i) => sha256Hex(`leaf-${i}`));

describe('buildMerkleRoot', () => {
  it('empty input has an explicit null result, never a fabricated root', () => {
    expect(buildMerkleRoot([])).toBeNull();
  });

  it('a single leaf is its own root', () => {
    const leaves = L(1);
    expect(buildMerkleRoot(leaves)).toBe(leaves[0]);
  });

  it('2 leaves', () => {
    const leaves = L(2);
    const expected = sha256Hex(leaves[0] + leaves[1]);
    expect(buildMerkleRoot(leaves)).toBe(expected);
  });

  it('3 leaves (odd count) — the last leaf is duplicated per the documented odd-node rule', () => {
    const leaves = L(3);
    const level1 = [sha256Hex(leaves[0] + leaves[1]), sha256Hex(leaves[2] + leaves[2])];
    const expected = sha256Hex(level1[0] + level1[1]);
    expect(buildMerkleRoot(leaves)).toBe(expected);
  });

  it('4 leaves (balanced tree)', () => {
    const leaves = L(4);
    const level1 = [sha256Hex(leaves[0] + leaves[1]), sha256Hex(leaves[2] + leaves[3])];
    const expected = sha256Hex(level1[0] + level1[1]);
    expect(buildMerkleRoot(leaves)).toBe(expected);
  });

  it('odd number of leaves at a higher count (5) still produces a deterministic root', () => {
    const leaves = L(5);
    const root1 = buildMerkleRoot(leaves);
    const root2 = buildMerkleRoot(leaves);
    expect(root1).toBe(root2);
    expect(root1).not.toBeNull();
  });

  it('duplicate leaf VALUES (not just odd count) are hashed as given — no implicit deduplication', () => {
    const leaf = sha256Hex('same-evidence-hash');
    const leaves = [leaf, leaf];
    const expected = sha256Hex(leaf + leaf);
    expect(buildMerkleRoot(leaves)).toBe(expected);
  });

  it('is deterministic across repeated calculation', () => {
    const leaves = L(7);
    const roots = Array.from({ length: 5 }, () => buildMerkleRoot(leaves));
    expect(new Set(roots).size).toBe(1);
  });

  it('leaf order matters — reordering the same leaves changes the root', () => {
    const leaves = L(4);
    const reordered = [leaves[1], leaves[0], leaves[2], leaves[3]];
    expect(buildMerkleRoot(leaves)).not.toBe(buildMerkleRoot(reordered));
  });

  it('a single tampered leaf changes the root', () => {
    const leaves = L(6);
    const tampered = [...leaves];
    tampered[3] = sha256Hex('tampered-value');
    expect(buildMerkleRoot(leaves)).not.toBe(buildMerkleRoot(tampered));
  });
});

describe('buildMerkleProof / verifyMerkleProof', () => {
  it('a valid proof verifies against the real root for every leaf position, across several tree sizes', () => {
    for (const n of [1, 2, 3, 4, 5, 7, 8]) {
      const leaves = L(n);
      const root = buildMerkleRoot(leaves)!;
      for (let i = 0; i < n; i++) {
        const proof = buildMerkleProof(leaves, i);
        expect(verifyMerkleProof(leaves[i], proof, root)).toBe(true);
      }
    }
  });

  it('a proof for the wrong leaf hash fails verification', () => {
    const leaves = L(4);
    const root = buildMerkleRoot(leaves)!;
    const proof = buildMerkleProof(leaves, 0);
    expect(verifyMerkleProof(sha256Hex('not-a-real-leaf'), proof, root)).toBe(false);
  });

  it('throws for an out-of-range index rather than silently returning a wrong proof', () => {
    const leaves = L(3);
    expect(() => buildMerkleProof(leaves, 3)).toThrow();
    expect(() => buildMerkleProof(leaves, -1)).toThrow();
  });
});
