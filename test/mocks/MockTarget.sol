// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract MockTarget {
    uint256 public value;
    address public immutable self = address(this);

    event Access(address sender);

    function set(uint256 _value) public returns (uint256) {
        if (_value == type(uint256).max) revert();
        emit Access(msg.sender);
        value = _value;
        return _value;
    }

    function setAccessControl(uint256 _value) public returns (uint256) {
        if (msg.sender != address(this)) {
            revert("MockTarget: not authorized");
        }
        value = _value;
        return _value;
    }

    function delegateCallTest() public view {
        // Check if this was called by a delegatecall
        if (address(this) == self) {
            revert("MockTarget: not delegatecall");
        }
    }
}
