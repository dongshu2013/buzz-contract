// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Buzz {
    string public message;
    address public owner;

    event MessageUpdated(string newMessage);

    constructor(string memory _initialMessage) {
        message = _initialMessage;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not the contract owner");
        _;
    }

    function updateMessage(string memory _newMessage) public onlyOwner {
        message = _newMessage;
        emit MessageUpdated(_newMessage);
    }
}
