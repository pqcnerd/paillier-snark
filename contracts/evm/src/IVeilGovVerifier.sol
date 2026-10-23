// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVeilGovVerifier {
    function verify(bytes calldata seal, bytes32 journalDigest) external view returns (bool);
}
