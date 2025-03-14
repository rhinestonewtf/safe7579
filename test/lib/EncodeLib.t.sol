// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { BaseTest } from "../ERC7579Compliance/Base.t.sol";
import { Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { MockTarget } from "../mocks/MockTarget.sol";

contract ExecutionLibTest is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    function test_EncodeBatch() public view {
        // Create a batch of executions
        Execution[] memory executions = new Execution[](2);

        bytes memory callData1 = abi.encodeCall(MockTarget.set, (1337));
        bytes memory callData2 = abi.encodeCall(MockTarget.set, (7331));

        executions[0] = Execution({ target: address(target), value: 0, callData: callData1 });
        executions[1] = Execution({ target: address(target), value: 100, callData: callData2 });

        // Encode the batch
        bytes memory encoded = ExecutionLib.encodeBatch(executions);

        // Verify it's not empty
        assertTrue(encoded.length > 0);

        // Decode and verify it matches the original
        Execution[] memory decoded = abi.decode(encoded, (Execution[]));

        assertEq(decoded.length, executions.length);
        assertEq(decoded[0].target, executions[0].target);
        assertEq(decoded[0].value, executions[0].value);
        assertEq(decoded[0].callData, executions[0].callData);
        assertEq(decoded[1].target, executions[1].target);
        assertEq(decoded[1].value, executions[1].value);
        assertEq(decoded[1].callData, executions[1].callData);
    }

    function test_EncodeSingle() public view {
        // Create single execution data
        address testTarget = address(target);
        uint256 testValue = 1337;
        bytes memory testCallData = abi.encodeCall(MockTarget.set, (7331));

        // Encode single execution
        bytes memory encoded = ExecutionLib.encodeSingle(testTarget, testValue, testCallData);

        // Verify it's not empty
        assertTrue(encoded.length > 0);
    }

    function test_DecodeBatchError() public {
        // Create an invalid batch encoding that should trigger the decoding error

        // Case 1: Invalid offset value
        bytes memory invalidBatch1 =
            hex"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000";

        vm.expectRevert(bytes4(0xba597e7e));
        this.callDecodeBatch(invalidBatch1);

        // Case 2: Length larger than available data
        bytes memory invalidBatch2 =
            hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000FFFF";

        vm.expectRevert(bytes4(0xba597e7e));
        this.callDecodeBatch(invalidBatch2);

        // Case 3: Invalid pointer in execution array element
        bytes memory invalidBatch3 =
            hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

        vm.expectRevert(bytes4(0xba597e7e));
        this.callDecodeBatch(invalidBatch3);
    }

    // Helper function to call decodeBatch externally to trigger reverts
    function callDecodeBatch(bytes calldata data) external pure returns (Execution[] memory) {
        return ExecutionLib.decodeBatch(data);
    }
}
