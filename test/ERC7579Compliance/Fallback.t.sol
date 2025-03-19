// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./ModuleManagement.t.sol";
import { ModeLib, CALLTYPE_SINGLE, CALLTYPE_STATIC } from "src/lib/ModeLib.sol";
import { MockFallback } from "../mocks/MockFallback.sol";
import "forge-std/console2.sol";

interface MockFallbackInterface {
    function target(uint256 value) external returns (uint256, address, address);
    function target2(uint256 value) external returns (uint256, address, address);
    function incrementCounter(uint256 amount) external returns (uint256, address);
    function getCounterAndCaller() external view returns (uint256, address);
    function resetCounter() external;
    function counter() external view returns (uint256);
    function onERC721Received(
        address,
        address,
        uint256,
        bytes calldata
    )
        external
        returns (uint256, address, address);
    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    )
        external
        returns (uint256, address, address);
    function onERC1155BatchReceived(
        address,
        address,
        uint256[] calldata,
        uint256[] calldata,
        bytes calldata
    )
        external
        returns (uint256, address, address);
    function doesNotExist(uint256 value) external returns (uint256);
}

contract FallbackTest is BaseTest {
    MockFallback mockFallbackModule;
    bytes _installData;

    function setUp() public virtual override {
        super.setUp();
        mockFallbackModule = new MockFallback();
        _installData = hex"4141414141414141";
    }

    function test_WhenInstallingSingleFallback() external {
        // Install fallback handler for the target function
        bytes4 fnSelector = MockFallbackInterface.target.selector;
        vm.startPrank(address(entrypoint));

        account.installModule(
            3, // MODULE_TYPE_FALLBACK
            address(mockFallbackModule),
            abi.encode(fnSelector, CALLTYPE_SINGLE, _installData)
        );
        vm.stopPrank();

        // Call the fallback function
        uint256 value = 1337;
        (uint256 returnValue, address msgSender, address msgSenderContext) =
            MockFallbackInterface(address(account)).target(value);

        // Verify return values
        assertEq(returnValue, value);
        assertEq(msgSender, address(account));
        assertEq(msgSenderContext, address(this)); // Verify ERC2771 sender is correctly passed
    }

    function test_WhenInstallingStaticFallback() external {
        // Install fallback handler for the target function with STATIC calltype
        bytes4 fnSelector = MockFallbackInterface.target.selector;
        vm.startPrank(address(entrypoint));

        account.installModule(
            3, // MODULE_TYPE_FALLBACK
            address(mockFallbackModule),
            abi.encode(fnSelector, CALLTYPE_STATIC, _installData)
        );
        vm.stopPrank();

        // Call the fallback function
        uint256 value = 42;
        (uint256 returnValue, address msgSender, address msgSenderContext) =
            MockFallbackInterface(address(account)).target(value);

        // Verify return values
        assertEq(returnValue, value);
        assertEq(msgSender, address(account));
        assertEq(msgSenderContext, address(this));
    }

    function test_WhenInstallingMultipleFallbacks() external {
        bytes4 fnSelector1 = MockFallbackInterface.target.selector;
        bytes4 fnSelector2 = MockFallbackInterface.target2.selector;

        vm.startPrank(address(entrypoint));

        // Install first fallback handler
        account.installModule(
            3, address(mockFallbackModule), abi.encode(fnSelector1, CALLTYPE_SINGLE, _installData)
        );

        // Install second fallback handler
        account.installModule(
            3, address(mockFallbackModule), abi.encode(fnSelector2, CALLTYPE_SINGLE, _installData)
        );

        vm.stopPrank();

        // Call both fallback functions
        uint256 value1 = 1337;
        uint256 value2 = 7331;

        (uint256 returnValue1, address msgSender1, address msgSenderContext1) =
            MockFallbackInterface(address(account)).target(value1);

        (uint256 returnValue2, address thisAddr, address msgSender2) =
            MockFallbackInterface(address(account)).target2(value2);

        // Verify return values
        assertEq(returnValue1, value1);
        assertEq(msgSender1, address(account));
        assertEq(msgSenderContext1, address(this));

        assertEq(returnValue2, value2);
        assertEq(thisAddr, address(mockFallbackModule));
        assertEq(msgSender2, address(account));
    }

    function test_WhenUninstallingFallback() external {
        bytes4 fnSelector = MockFallbackInterface.target.selector;

        vm.startPrank(address(entrypoint));

        // Install fallback handler
        account.installModule(
            3, address(mockFallbackModule), abi.encode(fnSelector, CALLTYPE_SINGLE, _installData)
        );

        // Call works before uninstalling
        vm.stopPrank();
        MockFallbackInterface(address(account)).target(1);

        // Uninstall the fallback handler
        vm.startPrank(address(entrypoint));
        account.uninstallModule(
            3, address(mockFallbackModule), abi.encode(fnSelector, _installData)
        );
        vm.stopPrank();

        // Call should revert after uninstalling
        vm.expectRevert();
        MockFallbackInterface(address(account)).target(1);
    }

    function test_WhenNoFallbackInstalled() external {
        // Calling a function with no fallback handler should revert
        vm.expectRevert();
        MockFallbackInterface(address(account)).target(1337);
    }

    function test_WhenInstallingFallbackWithInvalidCallType() external {
        bytes4 fnSelector = MockFallbackInterface.target.selector;

        vm.startPrank(address(entrypoint));

        // Try to install with invalid call type (only SINGLE and STATIC are allowed)
        uint256 invalidCallType = 3; // Not CALLTYPE_SINGLE or CALLTYPE_STATIC

        vm.expectRevert();
        account.installModule(
            3, address(mockFallbackModule), abi.encode(fnSelector, invalidCallType, _installData)
        );

        vm.stopPrank();
    }

    function test_WhenFallbackReceivesERC721() external {
        // This tests the default ERC721/1155 receiver pattern
        bytes4 erc721ReceiverSelector =
            bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));

        vm.startPrank(address(0xABCD)); // Random caller

        // Call the ERC721 receiver function directly on the account
        (bool success, bytes memory returnData) = address(account).call(
            abi.encodeWithSelector(erc721ReceiverSelector, address(this), address(this), 1, "")
        );

        // Should succeed even without explicit fallback handler for ERC721
        assertTrue(success);
        assertEq(bytes4(returnData), erc721ReceiverSelector);

        vm.stopPrank();
    }

    function test_WhenFallbackReceivesERC1155() external {
        // This tests the default ERC1155 receiver pattern
        bytes4 erc1155ReceiverSelector =
            bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));

        vm.startPrank(address(0xABCD)); // Random caller

        // Call the ERC1155 receiver function directly on the account
        (bool success, bytes memory returnData) = address(account).call(
            abi.encodeWithSelector(erc1155ReceiverSelector, address(this), address(this), 1, 1, "")
        );

        // Should succeed even without explicit fallback handler for ERC1155
        assertTrue(success);
        assertEq(bytes4(returnData), erc1155ReceiverSelector);

        vm.stopPrank();
    }

    function test_WhenFallbackReceivesERC1155Batch() external {
        // This tests the default ERC1155 batch receiver pattern
        bytes4 erc1155BatchReceiverSelector =
            bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));

        vm.startPrank(address(0xABCD)); // Random caller

        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10;
        amounts[1] = 20;

        // Call the ERC1155 batch receiver function directly on the account
        (bool success, bytes memory returnData) = address(account).call(
            abi.encodeWithSelector(
                erc1155BatchReceiverSelector, address(this), address(this), ids, amounts, ""
            )
        );

        // Should succeed even without explicit fallback handler for ERC1155
        assertTrue(success);
        assertEq(bytes4(returnData), erc1155BatchReceiverSelector);

        vm.stopPrank();
    }

    function test_WhenOverridingERC721Receiver() external {
        // Define the ERC721 receiver selector
        bytes4 erc721ReceiverSelector =
            bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));

        // Install custom fallback handler for the ERC721 receiver
        vm.startPrank(address(entrypoint));
        account.installModule(
            3, // MODULE_TYPE_FALLBACK
            address(mockFallbackModule),
            abi.encode(erc721ReceiverSelector, CALLTYPE_SINGLE, _installData)
        );
        vm.stopPrank();

        // Call the ERC721 receiver function
        vm.startPrank(address(0xABCD));

        // Encode parameters for onERC721Received
        bytes memory callData = abi.encodeWithSelector(
            erc721ReceiverSelector,
            address(this), // operator
            address(this), // from
            uint256(123), // tokenId
            bytes("") // data
        );

        // Call directly
        (bool success, bytes memory returnData) = address(account).call(callData);

        // Should succeed with our custom logic
        assertTrue(success);

        // Decode the return data to compare with expected values
        (uint256 tokenId, address moduleAddress, address accountAddress) =
            abi.decode(returnData, (uint256, address, address));

        // Verify custom handler was used
        assertEq(tokenId, 123); // Value passed in
        assertEq(moduleAddress, address(mockFallbackModule)); // address(this) from mock
        assertEq(accountAddress, address(account)); // msg.sender in mock

        vm.stopPrank();
    }

    function test_WhenOverridingERC1155Receivers() external {
        // Define the ERC1155 receiver selectors
        bytes4 erc1155ReceiverSelector =
            bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
        bytes4 erc1155BatchReceiverSelector =
            bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));

        // Install custom fallback handlers for both ERC1155 receiver functions
        vm.startPrank(address(entrypoint));

        // Install single transfer handler
        account.installModule(
            3,
            address(mockFallbackModule),
            abi.encode(erc1155ReceiverSelector, CALLTYPE_SINGLE, _installData)
        );

        // Install batch transfer handler
        account.installModule(
            3,
            address(mockFallbackModule),
            abi.encode(erc1155BatchReceiverSelector, CALLTYPE_SINGLE, _installData)
        );

        vm.stopPrank();

        // Test single transfer override
        vm.startPrank(address(0xABCD));

        bytes memory singleCallData = abi.encodeWithSelector(
            erc1155ReceiverSelector,
            address(this), // operator
            address(this), // from
            uint256(456), // id
            uint256(10), // amount
            bytes("") // data
        );

        (bool singleSuccess, bytes memory singleReturnData) = address(account).call(singleCallData);

        assertTrue(singleSuccess);
        (uint256 singleTokenId, address singleModuleAddress, address singleAccountAddress) =
            abi.decode(singleReturnData, (uint256, address, address));

        assertEq(singleTokenId, 456);
        assertEq(singleModuleAddress, address(mockFallbackModule));
        assertEq(singleAccountAddress, address(account));

        // Test batch transfer override
        uint256[] memory ids = new uint256[](2);
        ids[0] = 1;
        ids[1] = 2;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10;
        amounts[1] = 20;

        bytes memory batchCallData = abi.encodeWithSelector(
            erc1155BatchReceiverSelector,
            address(this), // operator
            address(this), // from
            ids, // ids
            amounts, // amounts
            bytes("") // data
        );

        (bool batchSuccess, bytes memory batchReturnData) = address(account).call(batchCallData);

        assertTrue(batchSuccess);
        (uint256 batchValue, address batchModuleAddress, address batchAccountAddress) =
            abi.decode(batchReturnData, (uint256, address, address));

        // For batch calls, we expect the first ID value
        assertEq(batchValue, 1);
        assertEq(batchModuleAddress, address(mockFallbackModule));
        assertEq(batchAccountAddress, address(account));

        vm.stopPrank();
    }

    function test_StaticFallbackCannotModifyState() external {
        // Reset counter to have a clean starting point
        mockFallbackModule.resetCounter();
        assertEq(mockFallbackModule.counter(), 0);

        // Install incrementCounter with STATIC calltype
        bytes4 incrementSelector = MockFallbackInterface.incrementCounter.selector;

        vm.startPrank(address(entrypoint));
        account.installModule(
            3,
            address(mockFallbackModule),
            abi.encode(incrementSelector, CALLTYPE_STATIC, _installData)
        );
        vm.stopPrank();

        // Call the function through the account
        uint256 incrementAmount = 5;

        // Static call will revert when trying to modify state
        vm.expectRevert();
        MockFallbackInterface(address(account)).incrementCounter(incrementAmount);

        // State should remain unchanged
        assertEq(mockFallbackModule.counter(), 0, "Counter should not be modified");
    }

    function test_SingleFallbackCanModifyState() external {
        // Reset counter to have a clean starting point
        mockFallbackModule.resetCounter();
        assertEq(mockFallbackModule.counter(), 0);

        // Install incrementCounter with SINGLE calltype
        bytes4 incrementSelector = MockFallbackInterface.incrementCounter.selector;

        vm.startPrank(address(entrypoint));
        account.installModule(
            3,
            address(mockFallbackModule),
            abi.encode(incrementSelector, CALLTYPE_SINGLE, _installData)
        );
        vm.stopPrank();

        // Call the function through the account
        uint256 incrementAmount = 5;
        (uint256 returnValue, address caller) =
            MockFallbackInterface(address(account)).incrementCounter(incrementAmount);

        // The function returns values
        assertEq(caller, address(account));

        // And the state should be modified because it was a single call
        assertEq(
            mockFallbackModule.counter(),
            incrementAmount,
            "Counter should be incremented in single call"
        );

        // Call it again to verify it's really incrementing
        MockFallbackInterface(address(account)).incrementCounter(incrementAmount);
        assertEq(
            mockFallbackModule.counter(), incrementAmount * 2, "Counter should be incremented twice"
        );
    }

    function test_ViewFunctionWithStaticCall() external {
        // Set up initial counter value
        mockFallbackModule.resetCounter();

        // Set counter to non-zero value
        vm.startPrank(address(entrypoint));

        // Install the increment function to set initial counter value
        account.installModule(
            3,
            address(mockFallbackModule),
            abi.encode(
                MockFallbackInterface.incrementCounter.selector, CALLTYPE_SINGLE, _installData
            )
        );

        // Install the view function with STATIC
        account.installModule(
            3,
            address(mockFallbackModule),
            abi.encode(
                MockFallbackInterface.getCounterAndCaller.selector, CALLTYPE_STATIC, _installData
            )
        );

        vm.stopPrank();

        // First set counter to a value
        uint256 initialValue = 42;
        MockFallbackInterface(address(account)).incrementCounter(initialValue);

        // Now call the view function
        (uint256 counterValue, address caller) =
            MockFallbackInterface(address(account)).getCounterAndCaller();

        // View function should return the current values
        assertEq(counterValue, initialValue, "View function should return correct counter value");
        assertEq(caller, address(account), "View function should return correct caller");
    }

    function test_GetFallbackHandlerBySelector() external {
        // Install a fallback handler
        bytes4 fnSelector = MockFallbackInterface.target.selector;

        vm.startPrank(address(entrypoint));

        account.installModule(
            3, // MODULE_TYPE_FALLBACK
            address(mockFallbackModule),
            abi.encode(fnSelector, CALLTYPE_SINGLE, _installData)
        );

        // Get the installed handler
        (CallType calltype, address handler) = account.getFallbackHandlerBySelector(fnSelector);

        // Verify correct values are returned
        assertEq(
            handler,
            address(mockFallbackModule),
            "Should return the correct fallback handler address"
        );
        assertTrue(calltype == CALLTYPE_SINGLE, "Should return the correct call type");

        // Test for a non-existent handler
        bytes4 nonExistentSelector = MockFallbackInterface.doesNotExist.selector;
        (CallType nullCalltype, address nullHandler) =
            account.getFallbackHandlerBySelector(nonExistentSelector);

        // Should return address(0) for non-existent handlers
        assertEq(nullHandler, address(0), "Should return address(0) for non-existent handlers");

        vm.stopPrank();
    }

    function test_GetFallbackHandlerAfterUninstall() external {
        // First install a handler
        bytes4 fnSelector = MockFallbackInterface.target.selector;

        vm.startPrank(address(entrypoint));

        account.installModule(
            3, // MODULE_TYPE_FALLBACK
            address(mockFallbackModule),
            abi.encode(fnSelector, CALLTYPE_SINGLE, _installData)
        );

        // Verify it's installed
        (CallType calltype, address handler) = account.getFallbackHandlerBySelector(fnSelector);
        assertEq(handler, address(mockFallbackModule), "Handler should be installed");

        // Uninstall the handler
        account.uninstallModule(
            3, address(mockFallbackModule), abi.encode(fnSelector, _installData)
        );

        // Verify it's removed
        (CallType uninstalledCalltype, address uninstalledHandler) =
            account.getFallbackHandlerBySelector(fnSelector);
        assertEq(uninstalledHandler, address(0), "Handler should be removed after uninstall");

        vm.stopPrank();
    }

    function test_GetFallbackHandlersWithDifferentCallTypes() external {
        bytes4 fnSelector1 = MockFallbackInterface.target.selector;
        bytes4 fnSelector2 = MockFallbackInterface.target2.selector;

        vm.startPrank(address(entrypoint));

        // Install first function with SINGLE calltype
        account.installModule(
            3, address(mockFallbackModule), abi.encode(fnSelector1, CALLTYPE_SINGLE, _installData)
        );

        // Install second function with STATIC calltype
        account.installModule(
            3, address(mockFallbackModule), abi.encode(fnSelector2, CALLTYPE_STATIC, _installData)
        );

        // Verify each handler's calltype is correctly returned
        (CallType calltype1, address handler1) = account.getFallbackHandlerBySelector(fnSelector1);
        (CallType calltype2, address handler2) = account.getFallbackHandlerBySelector(fnSelector2);

        // Check handlers
        assertEq(handler1, address(mockFallbackModule), "First handler should match");
        assertEq(handler2, address(mockFallbackModule), "Second handler should match");

        // Check call types
        assertTrue(calltype1 == CALLTYPE_SINGLE, "First calltype should be SINGLE");
        assertTrue(calltype2 == CALLTYPE_STATIC, "Second calltype should be STATIC");

        vm.stopPrank();
    }
}
