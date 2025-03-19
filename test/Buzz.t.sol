// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {Buzz} from "../src/Buzz.sol";

contract BuzzTest is Test {
    event MessageUpdated(string newMessage);
    
    Buzz public buzz;
    address public owner;
    address public user;
    string public constant INITIAL_MESSAGE = "Hello, Buzz!";

    function setUp() public {
        owner = address(this);
        user = address(0x1);
        buzz = new Buzz(INITIAL_MESSAGE);
    }

    function test_InitialMessage() public view {
        assertEq(buzz.message(), INITIAL_MESSAGE);
    }

    function test_InitialOwner() public view {
        assertEq(buzz.owner(), owner);
    }

    function test_UpdateMessage() public {
        string memory newMessage = "Updated message";
        buzz.updateMessage(newMessage);
        assertEq(buzz.message(), newMessage);
    }

    function test_RevertWhen_NonOwnerUpdatesMessage() public {
        vm.prank(user);
        vm.expectRevert("Not the contract owner");
        buzz.updateMessage("Should fail");
    }

    function test_UpdateMessageEmitsEvent() public {
        string memory newMessage = "Event test message";
        vm.expectEmit();
        emit MessageUpdated(newMessage);
        buzz.updateMessage(newMessage);
    }
}
