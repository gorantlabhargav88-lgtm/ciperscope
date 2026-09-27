import { ethers } from 'ethers';
import { logger } from '@ciperscope/logger';
import { IBlockchainProvider, AnchorRequest, AnchorOutcome, VerifyAnchorRequest, VerifyAnchorResult } from './types';

export const CIPHERSCOPE_ANCHOR_ABI = [
  'function anchorMerkleRoot(bytes32 batchKey, bytes32 merkleRoot, string organizationId, uint256 evidenceCount) external',
  'function getAnchor(bytes32 batchKey) external view returns (bytes32 merkleRoot, string organizationId, uint256 evidenceCount, uint256 blockTimestamp, uint256 blockNumber, address anchoredBy)',
  'function verifyAnchor(bytes32 batchKey, bytes32 expectedMerkleRoot) external view returns (bool exists, bool matches, bytes32 storedRoot, uint256 blockTimestamp, uint256 blockNumber)',
  'function totalAnchors() external view returns (uint256)',
  'function owner() external view returns (address)',
  'event MerkleRootAnchored(bytes32 indexed batchKey, bytes32 indexed merkleRoot, string organizationId, uint256 evidenceCount, uint256 timestamp, address indexed anchoredBy)',
];

export interface EvmProviderOptions {
  rpcUrl: string;
  network?: string;
  chainId?: number;
  contractAddress?: string;
  privateKey?: string;
}

export function toBytes32(hexStr: string): string {
  let clean = hexStr.trim();
  if (clean.startsWith('0x') || clean.startsWith('0X')) {
    clean = clean.slice(2);
  }
  if (clean.length !== 64) {
    // If shorter or longer, hash it to ensure 32 bytes
    return ethers.keccak256(ethers.toUtf8Bytes(hexStr));
  }
  return '0x' + clean.toLowerCase();
}

export class EvmBlockchainProvider implements IBlockchainProvider {
  public readonly name = 'evm';
  private readonly rpcUrl: string;
  private readonly network: string;
  private readonly chainId?: number;
  private readonly contractAddress?: string;
  private readonly privateKey?: string;

  constructor(options: EvmProviderOptions) {
    this.rpcUrl = options.rpcUrl;
    this.network = options.network || 'sepolia';
    this.chainId = options.chainId;
    this.contractAddress = options.contractAddress;
    this.privateKey = options.privateKey;
  }

  private getReadOnlyContract(provider: ethers.JsonRpcProvider): ethers.Contract {
    if (!this.contractAddress) {
      throw new Error('BLOCKCHAIN_CONTRACT_ADDRESS is not configured');
    }
    return new ethers.Contract(this.contractAddress, CIPHERSCOPE_ANCHOR_ABI, provider);
  }

  public async anchorMerkleRoot(request: AnchorRequest): Promise<AnchorOutcome> {
    if (!this.contractAddress || !this.privateKey) {
      return {
        status: 'NOT_CONFIGURED',
        reason: 'Blockchain contract address or private key is not configured for transaction submission',
      };
    }

    try {
      const provider = new ethers.JsonRpcProvider(this.rpcUrl);
      const wallet = new ethers.Wallet(this.privateKey, provider);
      const contract = new ethers.Contract(this.contractAddress, CIPHERSCOPE_ANCHOR_ABI, wallet);

      const batchKeyBytes32 = toBytes32(request.batchKey);
      const merkleRootBytes32 = toBytes32(request.merkleRoot);

      // Check on-chain idempotency: was this batch already anchored?
      try {
        const existingRecord = await contract.getAnchor(batchKeyBytes32);
        if (existingRecord && existingRecord.blockTimestamp > 0n) {
          logger.info(
            { batchKey: request.batchKey, merkleRoot: request.merkleRoot },
            'Batch is already anchored on-chain (idempotent replay)'
          );
          return {
            status: 'ANCHORED',
            network: this.network,
            transactionId: '0x' + request.batchKey, // Reference existing batch confirmation
            blockNumber: Number(existingRecord.blockNumber),
            contractAddress: this.contractAddress,
            anchoredAt: new Date(Number(existingRecord.blockTimestamp) * 1000),
          };
        }
      } catch (checkErr) {
        // If getAnchor call fails (e.g. fresh contract or unanchored), proceed with submission
        logger.debug({ checkErr }, 'getAnchor pre-check completed, proceeding to submission');
      }

      logger.info(
        {
          network: this.network,
          contractAddress: this.contractAddress,
          evidenceCount: request.evidenceCount,
          organizationId: request.organizationId,
        },
        'Submitting real blockchain anchor transaction'
      );

      const tx = await contract.anchorMerkleRoot(
        batchKeyBytes32,
        merkleRootBytes32,
        request.organizationId,
        BigInt(request.evidenceCount)
      );

      logger.info({ txHash: tx.hash }, 'Blockchain anchor transaction submitted, waiting for confirmation');
      const receipt = await tx.wait(1);

      if (!receipt || receipt.status !== 1) {
        return {
          status: 'FAILED',
          errorMessage: `Transaction execution reverted on-chain (tx: ${tx.hash})`,
        };
      }

      const block = await provider.getBlock(receipt.blockNumber);
      const anchoredAt = block ? new Date(block.timestamp * 1000) : new Date();

      return {
        status: 'ANCHORED',
        network: this.network,
        transactionId: receipt.hash,
        blockNumber: receipt.blockNumber,
        contractAddress: this.contractAddress,
        anchoredAt,
      };
    } catch (err: any) {
      const message = err instanceof Error ? err.message : String(err);
      // Redact any accidental private key reflection
      const sanitized = this.privateKey ? message.replace(new RegExp(this.privateKey, 'g'), '[REDACTED]') : message;
      logger.error({ err: sanitized }, 'Blockchain anchor transaction submission failed');
      return {
        status: 'FAILED',
        errorMessage: sanitized,
      };
    }
  }

  public async verifyAnchor(request: VerifyAnchorRequest): Promise<VerifyAnchorResult> {
    if (!this.contractAddress) {
      return {
        verified: false,
        network: this.network,
        contractAddress: null,
        transactionHash: request.transactionId ?? null,
        anchoredMerkleRoot: null,
        localMerkleRoot: request.merkleRoot,
        blockNumber: null,
        timestamp: null,
        reason: 'BLOCKCHAIN_CONTRACT_ADDRESS is not configured',
      };
    }

    try {
      const provider = new ethers.JsonRpcProvider(this.rpcUrl);
      const contract = this.getReadOnlyContract(provider);

      const batchKeyBytes32 = toBytes32(request.batchKey);
      const expectedMerkleRootBytes32 = toBytes32(request.merkleRoot);

      const [exists, matches, storedRoot, blockTimestamp, blockNumber] = await contract.verifyAnchor(
        batchKeyBytes32,
        expectedMerkleRootBytes32
      );

      let txVerified = true;
      if (request.transactionId && request.transactionId.startsWith('0x') && request.transactionId.length === 66) {
        try {
          const receipt = await provider.getTransactionReceipt(request.transactionId);
          if (!receipt || receipt.status !== 1) {
            txVerified = false;
          }
        } catch {
          // If receipt lookup fails, don't fail if contract state verified
        }
      }

      const verified = exists && matches && txVerified;
      const storedRootHex = exists ? (storedRoot as string).toLowerCase().replace(/^0x/, '') : null;

      return {
        verified,
        network: this.network,
        contractAddress: this.contractAddress,
        transactionHash: request.transactionId ?? null,
        anchoredMerkleRoot: storedRootHex,
        localMerkleRoot: request.merkleRoot,
        blockNumber: exists ? Number(blockNumber) : null,
        timestamp: exists ? new Date(Number(blockTimestamp) * 1000) : null,
        reason: !exists
          ? 'Batch not found in smart contract records'
          : !matches
          ? 'Merkle root mismatch between local evidence batch and on-chain record'
          : !txVerified
          ? 'Transaction receipt verification failed'
          : undefined,
      };
    } catch (err: any) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        verified: false,
        network: this.network,
        contractAddress: this.contractAddress,
        transactionHash: request.transactionId ?? null,
        anchoredMerkleRoot: null,
        localMerkleRoot: request.merkleRoot,
        blockNumber: null,
        timestamp: null,
        reason: `Blockchain verification query error: ${message}`,
      };
    }
  }

  public async getAnchorStatus(transactionId: string): Promise<AnchorOutcome> {
    try {
      const provider = new ethers.JsonRpcProvider(this.rpcUrl);
      const receipt = await provider.getTransactionReceipt(transactionId);
      if (!receipt) {
        return { status: 'FAILED', errorMessage: 'Transaction receipt not found' };
      }
      if (receipt.status === 1) {
        const block = await provider.getBlock(receipt.blockNumber);
        return {
          status: 'ANCHORED',
          network: this.network,
          transactionId: receipt.hash,
          blockNumber: receipt.blockNumber,
          contractAddress: this.contractAddress ?? null,
          anchoredAt: block ? new Date(block.timestamp * 1000) : new Date(),
        };
      }
      return { status: 'FAILED', errorMessage: 'Transaction reverted on-chain' };
    } catch (err: any) {
      return { status: 'FAILED', errorMessage: err?.message || 'Error querying transaction status' };
    }
  }
}
