// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IVeilGovVerifier.sol";

/// @title VeilGovElection — canonical EVM ballot / nullifier registry (MVP)
/// @notice Reconstructs the exact canonical RISC Zero journal before consuming
///         nullifiers. The configured adapter must call a real RISC Zero
///         verifier router with a Groth16 seal (composite STARKs are off-chain).
contract VeilGovElection {
    uint32 public immutable protocolVersion;
    bytes32 public immutable electionDomain;
    IVeilGovVerifier public immutable verifier;
    bytes32 public ethSnapshotRoot;
    bytes32 public solSnapshotRoot;
    bytes32 public credentialRoot;
    bytes32 public paillierKeyHash;
    bytes32 public verifierId;

    uint64 public ballotCount;
    bytes32 public ballotRoot;
    bool public frozen;
    uint64 public votingDeadline;

    mapping(bytes32 => bool) public nullifierUsed;

    event BallotAccepted(
        uint64 indexed index,
        bytes32 leaf,
        bytes32 nId,
        bytes ciphertextHash
    );
    event ElectionFrozen(bytes32 ballotRoot, uint64 ballotCount);

    error Frozen();
    error DeadlinePassed();
    error NullifierReplay();
    error InvalidCiphertext();
    error InvalidProof();
    error InvalidStatement();
    error InvalidNullifierCount();

    constructor(
        uint32 protocolVersion_,
        bytes32 electionDomain_,
        bytes32 ethSnapshotRoot_,
        bytes32 solSnapshotRoot_,
        bytes32 credentialRoot_,
        bytes32 paillierKeyHash_,
        bytes32 verifierId_,
        IVeilGovVerifier verifier_,
        uint64 votingDeadline_
    ) {
        if (address(verifier_) == address(0)) revert InvalidProof();
        protocolVersion = protocolVersion_;
        electionDomain = electionDomain_;
        verifier = verifier_;
        ethSnapshotRoot = ethSnapshotRoot_;
        solSnapshotRoot = solSnapshotRoot_;
        credentialRoot = credentialRoot_;
        paillierKeyHash = paillierKeyHash_;
        verifierId = verifierId_;
        votingDeadline = votingDeadline_;
        ballotRoot = bytes32(0);
    }

    function _statementJournal(
        bytes calldata ciphertext,
        bytes32 nId,
        bytes32[] calldata nAccounts
    ) internal view returns (bytes memory journal) {
        journal = abi.encodePacked(
            protocolVersion,
            electionDomain,
            ethSnapshotRoot,
            solSnapshotRoot,
            credentialRoot,
            paillierKeyHash,
            nId,
            uint32(nAccounts.length)
        );
        for (uint256 i = 0; i < nAccounts.length; i++) {
            journal = bytes.concat(journal, nAccounts[i]);
        }
        journal = bytes.concat(journal, bytes4(uint32(ciphertext.length)), ciphertext);
    }

    function _statementDigest(bytes memory journal) internal pure returns (bytes32) {
        bytes memory tag = bytes("VEILGOV_BALLOT_STATEMENT_V1");
        return sha256(
            abi.encodePacked(
                uint32(tag.length),
                tag,
                uint32(journal.length),
                journal
            )
        );
    }

    /// @dev Keccak parent matching Rust `keccak_parent` domain tag encoding is
    ///      approximated here for MVP; production must match byte-for-byte vectors.
    function _hashLeaf(
        uint64 index,
        bytes32 statementDigest,
        bytes32 receiptHash,
        bytes calldata ciphertext,
        bytes32 nId,
        bytes32[] calldata nAccounts
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "VEILGOV_BALLOT_LEAF_V1",
                index,
                statementDigest,
                receiptHash,
                ciphertext,
                nId,
                nAccounts
            )
        );
    }

    function _hashNode(bytes32 left, bytes32 right) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("VEILGOV_BALLOT_LEAF_V1", left, right));
    }

    /// Append-only root update for a single new leaf (rebuild is O(n) off-chain;
    /// on-chain stores incremental pairwise fold for MVP simplicity via stored leaves hash chain).
    /// For MVP we store running root as keccak(prevRoot || leaf).
    function acceptBallot(
        bytes32 statementDigest,
        bytes32 receiptHash,
        bytes calldata ciphertext,
        bytes32 nId,
        bytes32[] calldata nAccounts,
        bytes calldata proof
    ) external {
        if (frozen) revert Frozen();
        if (block.timestamp > votingDeadline) revert DeadlinePassed();
        if (ciphertext.length != 512) revert InvalidCiphertext();
        if (nAccounts.length != 4) revert InvalidNullifierCount();

        bytes memory journal = _statementJournal(ciphertext, nId, nAccounts);
        if (_statementDigest(journal) != statementDigest) revert InvalidStatement();
        // Must match Rust `proof_commitment`: SHA256("VEILGOV_RISC0_RECEIPT_V1" || proof).
        if (receiptHash != sha256(abi.encodePacked("VEILGOV_RISC0_RECEIPT_V1", proof))) {
            revert InvalidStatement();
        }
        if (!verifier.verify(proof, sha256(journal))) revert InvalidProof();

        if (nullifierUsed[nId]) revert NullifierReplay();
        nullifierUsed[nId] = true;
        for (uint256 i = 0; i < nAccounts.length; i++) {
            if (nullifierUsed[nAccounts[i]]) revert NullifierReplay();
            nullifierUsed[nAccounts[i]] = true;
        }

        uint64 index = ballotCount;
        bytes32 leaf = _hashLeaf(index, statementDigest, receiptHash, ciphertext, nId, nAccounts);
        // Incremental commitment (exact Merkle proven off-chain by tally guest).
        ballotRoot = keccak256(abi.encodePacked(ballotRoot, leaf));
        ballotCount = index + 1;

        emit BallotAccepted(index, leaf, nId, keccak256(ciphertext));
    }

    function freeze() external {
        if (frozen) revert Frozen();
        frozen = true;
        emit ElectionFrozen(ballotRoot, ballotCount);
    }
}
