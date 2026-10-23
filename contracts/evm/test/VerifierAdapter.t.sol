// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/VerifierAdapter.sol";

contract MockRiscZeroVerifier is IRiscZeroVerifier {
    bool internal shouldRevert;

    function setShouldRevert(bool value) external {
        shouldRevert = value;
    }

    function verify(bytes calldata, bytes32, bytes32) external view {
        if (shouldRevert) revert("invalid proof");
    }
}

contract VerifierAdapterTest is Test {
    MockRiscZeroVerifier internal router;
    VerifierAdapter internal adapter;

    function setUp() public {
        router = new MockRiscZeroVerifier();
        adapter = new VerifierAdapter(router, bytes32(uint256(123)));
    }

    function testRoutesValidSeal() public view {
        assertTrue(adapter.verify(hex"01020304", bytes32(uint256(456))));
    }

    function testReturnsFalseWhenRouterRejects() public {
        router.setShouldRevert(true);
        assertFalse(adapter.verify(hex"01020304", bytes32(uint256(456))));
    }
}
