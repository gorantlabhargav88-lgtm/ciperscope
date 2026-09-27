# CipherScope Blockchain Anchoring Subsystem

This directory contains the immutable Smart Contract, compilation, and deployment tooling for CipherScope's decentralized evidence integrity anchoring pipeline.

## Architecture

The CipherScope blockchain anchoring pipeline enforces non-repudiation and cryptographic integrity for forensic evidence:

```
Evidence Collected
       ↓
SHA-256 Evidence Hash (Canonical JSON representation)
       ↓
Evidence Batch Selection (Tenant-isolated, SERIALIZABLE lock)
       ↓
Merkle Tree Generation (Odd-node duplication rule)
       ↓
Deterministic Merkle Root (32 bytes)
       ↓
BlockchainAnchor Record Created (Status: BATCHED)
       ↓
EVM Provider Called (CipherScopeAnchor.sol)
       ↓
Smart Contract anchors (batchKey, merkleRoot, orgId, count)
       ↓
Transaction Receipt Confirmed on Testnet
       ↓
Database Status Updated -> ANCHORED (TxHash, Block, Timestamp)
       ↓
ChainOfCustodyEvent Appended -> BLOCKCHAIN_ANCHORED
```

## Smart Contract: `CipherScopeAnchor.sol`

The contract is minimal, gas-efficient, and strictly privacy-preserving:
- **Zero Evidence Leakage**: Raw email files, RFC 822 contents, attachments, Gmail tokens, API keys, or IP addresses are **NEVER** posted to the blockchain.
- **Integrity Anchoring**: Only the 32-byte `merkleRoot`, the 32-byte `batchKey`, the `organizationId`, and `evidenceCount` are anchored.
- **Immutability & Idempotency**: Once a `batchKey` is anchored, it can never be rewritten or modified (`BatchAlreadyAnchored` error).
- **Public Verification**: Provides `verifyAnchor(batchKey, expectedMerkleRoot)` view method to cryptographically verify any anchor against the on-chain ledger without gas fees.

## Deployment to Sepolia Testnet

1. Ensure prerequisites in `.env`:
   ```bash
   BLOCKCHAIN_ENABLED=true
   BLOCKCHAIN_NETWORK=sepolia
   BLOCKCHAIN_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_ALCHEMY_KEY
   BLOCKCHAIN_PRIVATE_KEY=your_private_key_with_sepolia_eth
   ```

2. Compile the smart contract:
   ```bash
   pnpm run blockchain:compile
   # Or: npx tsx infra/blockchain/scripts/compile.ts
   ```

3. Deploy the smart contract:
   ```bash
   pnpm run blockchain:deploy
   # Or: npx tsx infra/blockchain/scripts/deploy.ts
   ```

4. Set the deployed address in `.env`:
   ```bash
   BLOCKCHAIN_CONTRACT_ADDRESS=0x...
   ```
