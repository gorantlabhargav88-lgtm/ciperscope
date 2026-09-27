import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NullBlockchainProvider } from '../NullBlockchainProvider';
import { EvmBlockchainProvider, toBytes32 } from '../EvmBlockchainProvider';
import { BlockchainProviderConfig } from '../BlockchainProviderConfig';
import { ethers } from 'ethers';

// Mock ethers
vi.mock('ethers', async () => {
  const actual = await vi.importActual<typeof import('ethers')>('ethers');
  return {
    ...actual,
    ethers: {
      ...actual.ethers,
      JsonRpcProvider: vi.fn(),
      Wallet: vi.fn(),
      Contract: vi.fn(),
    },
  };
});

describe('Blockchain Provider Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('NullBlockchainProvider (Disabled / Missing Config)', () => {
    it('returns NOT_CONFIGURED when disabled', async () => {
      const provider = new NullBlockchainProvider('Blockchain disabled');
      const outcome = await provider.anchorMerkleRoot({
        merkleRoot: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
        evidenceCount: 2,
        organizationId: 'org-test',
        batchKey: 'batch-test-123',
      });

      expect(outcome.status).toBe('NOT_CONFIGURED');
      if (outcome.status === 'NOT_CONFIGURED') {
        expect(outcome.reason).toContain('Blockchain disabled');
      }
    });

    it('returns unverified for verifyAnchor when not configured', async () => {
      const provider = new NullBlockchainProvider('Not configured');
      const result = await provider.verifyAnchor({
        batchKey: 'batch-test-123',
        merkleRoot: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
      });

      expect(result.verified).toBe(false);
      expect(result.reason).toContain('Not configured');
      expect(result.anchoredMerkleRoot).toBeNull();
    });
  });

  describe('toBytes32 Helper', () => {
    it('formats a 64-char hex string as 0x prefixed 32-byte hex', () => {
      const hex = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff';
      const formatted = toBytes32(hex);
      expect(formatted).toBe('0x' + hex.toLowerCase());
      expect(formatted.length).toBe(66);
    });

    it('handles strings already prefixed with 0x', () => {
      const hex = '0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff';
      const formatted = toBytes32(hex);
      expect(formatted).toBe(hex.toLowerCase());
    });
  });

  describe('EvmBlockchainProvider', () => {
    const mockRpcUrl = 'https://eth-sepolia.example.com';
    const mockContractAddress = '0x1234567890123456789012345678901234567890';
    const mockPrivateKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    it('returns NOT_CONFIGURED when contractAddress or privateKey is missing', async () => {
      const provider = new EvmBlockchainProvider({
        rpcUrl: mockRpcUrl,
      });

      const outcome = await provider.anchorMerkleRoot({
        merkleRoot: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
        evidenceCount: 1,
        organizationId: 'org-test',
        batchKey: 'batch-key-1',
      });

      expect(outcome.status).toBe('NOT_CONFIGURED');
    });

    it('submits a real transaction and confirms when transaction succeeds', async () => {
      const mockWait = vi.fn().mockResolvedValue({
        status: 1,
        hash: '0xmocktxhash1234567890abcdef1234567890abcdef1234567890abcdef12345678',
        blockNumber: 123456,
      });
      const mockAnchorMerkleRoot = vi.fn().mockResolvedValue({
        hash: '0xmocktxhash1234567890abcdef1234567890abcdef1234567890abcdef12345678',
        wait: mockWait,
      });
      const mockGetAnchor = vi.fn().mockResolvedValue({
        blockTimestamp: 0n,
      });

      (ethers.Contract as unknown as any).mockImplementation(() => ({
        getAnchor: mockGetAnchor,
        anchorMerkleRoot: mockAnchorMerkleRoot,
      }));

      (ethers.JsonRpcProvider as unknown as any).mockImplementation(() => ({
        getBlock: vi.fn().mockResolvedValue({ timestamp: 1700000000 }),
      }));

      const provider = new EvmBlockchainProvider({
        rpcUrl: mockRpcUrl,
        contractAddress: mockContractAddress,
        privateKey: mockPrivateKey,
        network: 'sepolia',
      });

      const outcome = await provider.anchorMerkleRoot({
        merkleRoot: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
        evidenceCount: 5,
        organizationId: 'org-test',
        batchKey: 'batch-test-success',
      });

      expect(outcome.status).toBe('ANCHORED');
      if (outcome.status === 'ANCHORED') {
        expect(outcome.network).toBe('sepolia');
        expect(outcome.transactionId).toBe('0xmocktxhash1234567890abcdef1234567890abcdef1234567890abcdef12345678');
        expect(outcome.blockNumber).toBe(123456);
        expect(outcome.contractAddress).toBe(mockContractAddress);
      }
    });

    it('returns FAILED when transaction execution reverts on-chain', async () => {
      const mockWait = vi.fn().mockResolvedValue({
        status: 0, // reverted
        hash: '0xrevertedtxhash',
      });
      const mockAnchorMerkleRoot = vi.fn().mockResolvedValue({
        hash: '0xrevertedtxhash',
        wait: mockWait,
      });

      (ethers.Contract as unknown as any).mockImplementation(() => ({
        getAnchor: vi.fn().mockResolvedValue({ blockTimestamp: 0n }),
        anchorMerkleRoot: mockAnchorMerkleRoot,
      }));

      const provider = new EvmBlockchainProvider({
        rpcUrl: mockRpcUrl,
        contractAddress: mockContractAddress,
        privateKey: mockPrivateKey,
      });

      const outcome = await provider.anchorMerkleRoot({
        merkleRoot: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
        evidenceCount: 1,
        organizationId: 'org-test',
        batchKey: 'batch-revert',
      });

      expect(outcome.status).toBe('FAILED');
      if (outcome.status === 'FAILED') {
        expect(outcome.errorMessage).toContain('reverted');
      }
    });

    it('idempotently handles already-anchored batch without sending a duplicate transaction', async () => {
      (ethers.Contract as unknown as any).mockImplementation(() => ({
        getAnchor: vi.fn().mockResolvedValue({
          blockTimestamp: 1700000000n,
          blockNumber: 99999n,
          merkleRoot: '0x11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
        }),
        anchorMerkleRoot: vi.fn(), // should NOT be called
      }));

      const provider = new EvmBlockchainProvider({
        rpcUrl: mockRpcUrl,
        contractAddress: mockContractAddress,
        privateKey: mockPrivateKey,
        network: 'sepolia',
      });

      const outcome = await provider.anchorMerkleRoot({
        merkleRoot: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
        evidenceCount: 3,
        organizationId: 'org-test',
        batchKey: 'batch-already-anchored',
      });

      expect(outcome.status).toBe('ANCHORED');
      if (outcome.status === 'ANCHORED') {
        expect(outcome.blockNumber).toBe(99999);
      }
    });

    it('sanitizes and redacts private key from error messages', async () => {
      (ethers.Contract as unknown as any).mockImplementation(() => ({
        getAnchor: vi.fn().mockResolvedValue({ blockTimestamp: 0n }),
        anchorMerkleRoot: vi.fn().mockRejectedValue(new Error(`Failed with key ${mockPrivateKey} at node`)),
      }));

      const provider = new EvmBlockchainProvider({
        rpcUrl: mockRpcUrl,
        contractAddress: mockContractAddress,
        privateKey: mockPrivateKey,
      });

      const outcome = await provider.anchorMerkleRoot({
        merkleRoot: '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff',
        evidenceCount: 1,
        organizationId: 'org-test',
        batchKey: 'batch-err',
      });

      expect(outcome.status).toBe('FAILED');
      if (outcome.status === 'FAILED') {
        expect(outcome.errorMessage).not.toContain(mockPrivateKey);
        expect(outcome.errorMessage).toContain('[REDACTED]');
      }
    });

    it('verifies anchor on-chain correctly', async () => {
      const mockMerkle = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff';
      (ethers.Contract as unknown as any).mockImplementation(() => ({
        verifyAnchor: vi.fn().mockResolvedValue([
          true, // exists
          true, // matches
          '0x' + mockMerkle,
          1700000000n,
          88888n,
        ]),
      }));

      (ethers.JsonRpcProvider as unknown as any).mockImplementation(() => ({
        getTransactionReceipt: vi.fn().mockResolvedValue({ status: 1 }),
      }));

      const provider = new EvmBlockchainProvider({
        rpcUrl: mockRpcUrl,
        contractAddress: mockContractAddress,
        network: 'sepolia',
      });

      const result = await provider.verifyAnchor({
        batchKey: 'batch-1',
        merkleRoot: mockMerkle,
        transactionId: '0x1234567890123456789012345678901234567890123456789012345678901234',
      });

      expect(result.verified).toBe(true);
      expect(result.network).toBe('sepolia');
      expect(result.contractAddress).toBe(mockContractAddress);
      expect(result.anchoredMerkleRoot).toBe(mockMerkle);
      expect(result.blockNumber).toBe(88888);
    });
  });
});
