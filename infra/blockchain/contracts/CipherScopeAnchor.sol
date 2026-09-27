// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title CipherScopeAnchor
 * @notice Minimal immutable evidence anchor contract for CipherScope digital forensics platform.
 * Anchors only cryptographic Merkle roots and batch identifiers.
 * No raw emails, attachments, credentials, or private evidence are ever stored on-chain.
 */
contract CipherScopeAnchor {
    struct AnchorRecord {
        bytes32 merkleRoot;
        string organizationId;
        uint256 evidenceCount;
        uint256 blockTimestamp;
        uint256 blockNumber;
        address anchoredBy;
    }

    // Mapping from batchKey => AnchorRecord
    mapping(bytes32 => AnchorRecord) private _anchors;

    // Ordered list of anchored batch keys for indexing/enumeration
    bytes32[] private _batchKeys;

    // Contract owner / deployer
    address public immutable owner;

    // Events
    event MerkleRootAnchored(
        bytes32 indexed batchKey,
        bytes32 indexed merkleRoot,
        string organizationId,
        uint256 evidenceCount,
        uint256 timestamp,
        address indexed anchoredBy
    );

    error BatchAlreadyAnchored(bytes32 batchKey);
    error InvalidMerkleRoot();
    error InvalidBatchKey();
    error Unauthorized();

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Anchors a Merkle root for a specific batch.
     * @dev Idempotent: once a batchKey is anchored, it cannot be overwritten or altered.
     * @param batchKey Deterministic SHA-256 hash representing the batch
     * @param merkleRoot The Merkle root of the batch (bytes32)
     * @param organizationId Tenant identifier for audit trail
     * @param evidenceCount Number of evidence items in the batch
     */
    function anchorMerkleRoot(
        bytes32 batchKey,
        bytes32 merkleRoot,
        string calldata organizationId,
        uint256 evidenceCount
    ) external onlyOwner {
        if (batchKey == bytes32(0)) revert InvalidBatchKey();
        if (merkleRoot == bytes32(0)) revert InvalidMerkleRoot();
        if (_anchors[batchKey].blockTimestamp != 0) revert BatchAlreadyAnchored(batchKey);

        _anchors[batchKey] = AnchorRecord({
            merkleRoot: merkleRoot,
            organizationId: organizationId,
            evidenceCount: evidenceCount,
            blockTimestamp: block.timestamp,
            blockNumber: block.number,
            anchoredBy: msg.sender
        });

        _batchKeys.push(batchKey);

        emit MerkleRootAnchored(
            batchKey,
            merkleRoot,
            organizationId,
            evidenceCount,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @notice Gets the anchor record for a given batch key.
     * @param batchKey The batch identifier
     */
    function getAnchor(bytes32 batchKey) external view returns (
        bytes32 merkleRoot,
        string memory organizationId,
        uint256 evidenceCount,
        uint256 blockTimestamp,
        uint256 blockNumber,
        address anchoredBy
    ) {
        AnchorRecord memory record = _anchors[batchKey];
        return (
            record.merkleRoot,
            record.organizationId,
            record.evidenceCount,
            record.blockTimestamp,
            record.blockNumber,
            record.anchoredBy
        );
    }

    /**
     * @notice Verifies if a given Merkle root matches the anchored record for a batch.
     * @param batchKey The batch identifier
     * @param expectedMerkleRoot The Merkle root to check
     * @return exists Whether the batch was anchored
     * @return matches Whether the stored Merkle root equals expectedMerkleRoot
     * @return storedRoot The actual Merkle root stored in the contract
     * @return blockTimestamp The timestamp when anchored
     * @return blockNumber The block number when anchored
     */
    function verifyAnchor(bytes32 batchKey, bytes32 expectedMerkleRoot) external view returns (
        bool exists,
        bool matches,
        bytes32 storedRoot,
        uint256 blockTimestamp,
        uint256 blockNumber
    ) {
        AnchorRecord memory record = _anchors[batchKey];
        if (record.blockTimestamp == 0) {
            return (false, false, bytes32(0), 0, 0);
        }
        return (
            true,
            record.merkleRoot == expectedMerkleRoot,
            record.merkleRoot,
            record.blockTimestamp,
            record.blockNumber
        );
    }

    /**
     * @notice Returns total number of anchored batches.
     */
    function totalAnchors() external view returns (uint256) {
        return _batchKeys.length;
    }

    /**
     * @notice Returns the batchKey at a given index.
     */
    function getBatchKeyAtIndex(uint256 index) external view returns (bytes32) {
        require(index < _batchKeys.length, "Index out of bounds");
        return _batchKeys[index];
    }
}
