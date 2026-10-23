// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VeilGovElection.sol";

contract MockVeilGovVerifier is IVeilGovVerifier {
    bool internal result = true;

    function setResult(bool result_) external {
        result = result_;
    }

    function verify(bytes calldata, bytes32) external view returns (bool) {
        return result;
    }
}

contract VeilGovElectionTest is Test {
    VeilGovElection internal election;
    MockVeilGovVerifier internal verifier;

    function setUp() public {
        verifier = new MockVeilGovVerifier();
        election = new VeilGovElection(
            1,
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            bytes32(uint256(6)),
            verifier,
            type(uint64).max
        );
    }

    function statementDigest(
        bytes memory ct,
        bytes32 nId,
        bytes32[] memory accounts
    ) internal pure returns (bytes32) {
        bytes memory journal = abi.encodePacked(
            uint32(1),
            bytes32(uint256(1)),
            bytes32(uint256(2)),
            bytes32(uint256(3)),
            bytes32(uint256(4)),
            bytes32(uint256(5)),
            nId,
            uint32(accounts.length)
        );
        for (uint256 i = 0; i < accounts.length; i++) {
            journal = bytes.concat(journal, accounts[i]);
        }
        journal = bytes.concat(journal, bytes4(uint32(ct.length)), ct);
        bytes memory tag = bytes("VEILGOV_BALLOT_STATEMENT_V1");
        return sha256(
            abi.encodePacked(uint32(tag.length), tag, uint32(journal.length), journal)
        );
    }

    function accounts() internal pure returns (bytes32[] memory values) {
        values = new bytes32[](4);
        for (uint256 i = 0; i < values.length; i++) {
            values[i] = bytes32(uint256(10 + i));
        }
    }

    function testAcceptAndFreeze() public {
        bytes memory ct = new bytes(512);
        bytes32[] memory accountNullifiers = accounts();
        bytes memory proof = hex"01020304";
        election.acceptBallot(
            statementDigest(ct, bytes32(uint256(9)), accountNullifiers),
            sha256(abi.encodePacked("VEILGOV_RISC0_RECEIPT_V1", proof)),
            ct,
            bytes32(uint256(9)),
            accountNullifiers,
            proof
        );
        assertEq(election.ballotCount(), 1);
        election.freeze();
        assertTrue(election.frozen());
    }

    function testNullifierReplay() public {
        bytes memory ct = new bytes(512);
        bytes32[] memory accountNullifiers = accounts();
        bytes memory proof = hex"01020304";
        bytes32 digest = statementDigest(ct, bytes32(uint256(9)), accountNullifiers);
        election.acceptBallot(
            digest,
            sha256(abi.encodePacked("VEILGOV_RISC0_RECEIPT_V1", proof)),
            ct,
            bytes32(uint256(9)),
            accountNullifiers,
            proof
        );
        vm.expectRevert(VeilGovElection.NullifierReplay.selector);
        election.acceptBallot(
            digest,
            sha256(abi.encodePacked("VEILGOV_RISC0_RECEIPT_V1", proof)),
            ct,
            bytes32(uint256(9)),
            accountNullifiers,
            proof
        );
    }

    function testChangedPublicInputRejected() public {
        bytes memory ct = new bytes(512);
        bytes32[] memory accountNullifiers = accounts();
        bytes memory proof = hex"01020304";
        bytes32 digest = statementDigest(ct, bytes32(uint256(9)), accountNullifiers);
        ct[0] = 1;
        vm.expectRevert(VeilGovElection.InvalidStatement.selector);
        election.acceptBallot(
            digest,
            sha256(abi.encodePacked("VEILGOV_RISC0_RECEIPT_V1", proof)),
            ct,
            bytes32(uint256(9)),
            accountNullifiers,
            proof
        );
    }

    function testInvalidProofRejected() public {
        bytes memory ct = new bytes(512);
        bytes32[] memory accountNullifiers = accounts();
        bytes memory proof = hex"01020304";
        verifier.setResult(false);
        vm.expectRevert(VeilGovElection.InvalidProof.selector);
        election.acceptBallot(
            statementDigest(ct, bytes32(uint256(9)), accountNullifiers),
            sha256(abi.encodePacked("VEILGOV_RISC0_RECEIPT_V1", proof)),
            ct,
            bytes32(uint256(9)),
            accountNullifiers,
            proof
        );
    }
}
