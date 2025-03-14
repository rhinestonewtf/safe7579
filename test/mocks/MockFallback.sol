// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MockFallback as MockFallbackBase } from "module-bases/mocks/MockFallback.sol";

contract MockFallback is MockFallbackBase {
    uint256 public counter = 0;

    function target(uint256 value)
        external
        returns (uint256 _value, address msgSender, address msgSenderContext)
    {
        _value = value;
        msgSender = msg.sender;
        msgSenderContext = _msgSender();
    }

    function target2(uint256 value)
        external
        returns (uint256 _value, address _this, address msgSender)
    {
        _value = value;
        _this = address(this);
        msgSender = msg.sender;
    }

    // Simple state-changing function
    function incrementCounter(uint256 amount) external returns (uint256, address) {
        counter += amount;
        return (counter, msg.sender);
    }

    // Simple view function (static)
    function getCounterAndCaller() external view returns (uint256, address) {
        return (counter, msg.sender);
    }

    // Reset counter for testing
    function resetCounter() external {
        counter = 0;
    }

    // Custom ERC721 receiver implementation - returns tuple instead of bytes4
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    )
        external
        returns (uint256, address, address)
    {
        // Return custom data to verify our implementation was used
        return (tokenId, address(this), msg.sender);
    }

    // Custom ERC1155 single token receiver implementation - returns tuple instead of bytes4
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256, address, address)
    {
        // Return custom data to verify our implementation was used
        return (id, address(this), msg.sender);
    }

    // Custom ERC1155 batch token receiver implementation - returns tuple instead of bytes4
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        external
        returns (uint256, address, address)
    {
        // Return the first ID if available, otherwise 0
        uint256 firstId = ids.length > 0 ? ids[0] : 0;
        return (firstId, address(this), msg.sender);
    }
}
