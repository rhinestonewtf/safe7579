// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Base.t.sol";
import {
    ExecType,
    ModeCode,
    ModeLib,
    ModePayload,
    MODE_DEFAULT,
    CallType,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL
} from "src/lib/ModeLib.sol";

contract Executions4337Test is BaseTest {
    error UnsupportedCallType(CallType callType);
    error UnsupportedExecType(ExecType execType);

    function setUp() public virtual override {
        super.setUp();
        installUnitTestAsModule();
    }

    function test_WhenExecutingOnValidTarget() external asEntryPoint {
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 1337);
        // It should pass
        account.execute(
            ModeLib.encodeSimpleSingle(),
            ExecutionLib.encodeSingle(address(target), uint256(0), setValueOnTarget)
        );
        assertEq(target.value(), 1337);

        setValueOnTarget = abi.encodeCall(MockTarget.set, 1336);
        Execution[] memory executions = new Execution[](2);
        MockTarget target2 = new MockTarget();
        executions[0] =
            Execution({ target: address(target2), value: 0, callData: setValueOnTarget });
        executions[1] = Execution({ target: address(target), value: 0, callData: setValueOnTarget });
        account.execute(ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(executions));
        assertEq(target2.value(), 1336);
        assertEq(target.value(), 1336);
    }

    function test_WhenExecutingSingleOnInvalidTarget() external asEntryPoint {
        // It should revert
        vm.expectRevert();
        account.execute(
            ModeLib.encodeSimpleSingle(),
            ExecutionLib.encodeSingle(address(target), uint256(0), hex"4141414141414141")
        );
    }

    function test_WhenTryExecutingOnValidTarget() external asEntryPoint {
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 1337);
        // It should pass
        account.execute(
            ModeLib.encode(
                CALLTYPE_SINGLE, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            ExecutionLib.encodeSingle(address(target), uint256(0), hex"41414145")
        );

        setValueOnTarget = abi.encodeCall(MockTarget.set, 1338);
        Execution[] memory executions = new Execution[](2);
        // this one will fail
        executions[0] = Execution({ target: address(target), value: 0, callData: hex"41414141" });
        // this one will execute
        executions[1] = Execution({ target: address(target), value: 0, callData: setValueOnTarget });
        account.execute(
            ModeLib.encode(CALLTYPE_BATCH, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(bytes22(0))),
            ExecutionLib.encodeBatch(executions)
        );

        assertEq(target.value(), 1338);
    }

    function test_WhenExecutingDelegateCall() external asEntryPoint {
        // Prepare delegatecall data - first 20 bytes are the target address, followed by the
        // calldata
        bytes memory delegateCallData =
            abi.encodePacked(address(target), abi.encodeCall(MockTarget.delegateCallTest, ()));

        // Execute delegatecall using CALLTYPE_DELEGATECALL
        account.execute(
            ModeLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            delegateCallData
        );
    }

    function test_WhenTryExecutingDelegateCall() external asEntryPoint {
        // Prepare successful delegatecall data
        bytes memory delegateCallData =
            abi.encodePacked(address(target), abi.encodeCall(MockTarget.setAccessControl, (1337)));

        // Execute try delegatecall
        account.execute(
            ModeLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            delegateCallData
        );

        // Assert state was changed
        assertEq(target.value(), 1337);

        // Try with failing data - invalid function signature
        bytes memory failingDelegateCallData = abi.encodePacked(
            address(target),
            hex"deadbeef" // Invalid function signature
        );

        // This should not revert thanks to TRY execution type
        account.execute(
            ModeLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            failingDelegateCallData
        );

        // Value should remain unchanged from the previous successful call
        assertEq(target.value(), 1337);
    }

    function test_WhenUnsupportedCallType() external asEntryPoint {
        // Test with an unsupported call type (a value that isn't CALLTYPE_SINGLE, CALLTYPE_BATCH,
        // or CALLTYPE_DELEGATECALL)
        CallType invalidCallType = CallType.wrap(0x04); // Assuming 0, 1, 2 are the supported types

        vm.expectRevert(abi.encodeWithSelector(UnsupportedCallType.selector, invalidCallType));

        account.execute(
            ModeLib.encode(
                invalidCallType, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            ExecutionLib.encodeSingle(address(target), 0, "")
        );

        // Try with EXECTYPE_TRY
        vm.expectRevert(abi.encodeWithSelector(UnsupportedCallType.selector, invalidCallType));

        account.execute(
            ModeLib.encode(
                invalidCallType, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            ExecutionLib.encodeSingle(address(target), 0, "")
        );
    }

    function test_WhenUnsupportedExecType() external asEntryPoint {
        // Test with an unsupported exec type (a value that isn't EXECTYPE_DEFAULT or EXECTYPE_TRY)
        ExecType invalidExecType = ExecType.wrap(0x02); // Assuming 0, 1 are the supported types

        vm.expectRevert(abi.encodeWithSelector(UnsupportedExecType.selector, invalidExecType));

        account.execute(
            ModeLib.encode(
                CALLTYPE_SINGLE, invalidExecType, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            ExecutionLib.encodeSingle(address(target), 0, "")
        );
    }

    function test_WhenExecutingDelegateCallReturn() external asEntryPoint {
        // Test executing a delegatecall that returns data
        bytes memory callData = abi.encodeCall(MockTarget.set, (1337));

        // Call the executor, which will call the account's executeFromExecutor
        bytes[] memory returnData =
            defaultExecutor.executeDelegateCallViaAccount(account, address(target), callData);

        // Verify we got the expected return data
        assertEq(returnData.length, 1);
        // The return data should contain the uint256 return value from MockTarget.set
        assertEq(abi.decode(returnData[0], (uint256)), 1337);
    }

    function test_WhenTryExecutingDelegateCallReturn() external asEntryPoint {
        // Test try executing a delegatecall that fails
        bytes memory failingCallData = abi.encodeCall(MockTarget.set, (type(uint256).max));

        // This should not revert due to TRY execution type
        bytes[] memory returnDataFromFailure = defaultExecutor.tryExecuteDelegateCallViaAccount(
            account, address(target), failingCallData
        );

        // Verify we got back an empty bytes array for the failed call
        assertEq(returnDataFromFailure.length, 1);
        assertEq(returnDataFromFailure[0].length, 0);
    }

    function test_ExecuteReturnUnsupportedCallType() external asEntryPoint {
        // Test with an unsupported call type
        bytes memory callData = abi.encodeCall(MockTarget.set, (1337));

        // Call should revert with UnsupportedCallType
        vm.expectRevert(abi.encodeWithSelector(UnsupportedCallType.selector, CallType.wrap(0x04)));

        defaultExecutor.executeUnsupportedCallType(account, address(target), callData);
    }

    function test_ExecuteReturnUnsupportedExecType() external asEntryPoint {
        // Test with an unsupported exec type
        bytes memory callData = abi.encodeCall(MockTarget.set, (1337));

        // Call should revert with UnsupportedExecType
        vm.expectRevert(abi.encodeWithSelector(UnsupportedExecType.selector, ExecType.wrap(0x02)));

        defaultExecutor.executeUnsupportedExecType(account, address(target), callData);
    }
}
