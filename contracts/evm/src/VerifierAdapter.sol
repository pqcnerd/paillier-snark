// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IVeilGovVerifier.sol";

/// @notice Minimal RISC Zero verifier-router interface. The production router
///         accepts a Groth16 seal (not a local composite STARK receipt). It
///         reverts when the seal, image ID, or journal digest is invalid.
interface IRiscZeroVerifier {
    function verify(
        bytes calldata seal,
        bytes32 imageId,
        bytes32 journalDigest
    ) external view;
}

contract VerifierAdapter is IVeilGovVerifier {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public immutable imageId;

    constructor(IRiscZeroVerifier verifier_, bytes32 imageId_) {
        require(address(verifier_) != address(0), "zero verifier");
        verifier = verifier_;
        imageId = imageId_;
    }

    function verify(bytes calldata seal, bytes32 journalDigest) external view returns (bool) {
        try verifier.verify(seal, imageId, journalDigest) {
            return true;
        } catch {
            return false;
        }
    }
}
