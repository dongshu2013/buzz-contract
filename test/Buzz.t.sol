// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Buzz} from "../src/Buzz.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("MockToken", "MTK") {
        _mint(msg.sender, 1000 ether);
    }
}

contract MockERC721 is ERC721 {
    constructor() ERC721("MockNFT", "MNFT") {
        _mint(msg.sender, 1);
        _mint(msg.sender, 2);
    }
}

contract MockERC1155 is ERC1155 {
    constructor() ERC1155("") {
        _mint(msg.sender, 1, 100, "");
        _mint(msg.sender, 2, 200, "");
    }
}

contract BuzzTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    Buzz public buzz;
    MockERC20 public token;
    MockERC721 public nft;
    MockERC1155 public multiToken;
    
    address public owner;
    address public user;
    address public user2;
    uint256 public ownerPrivateKey;

    function setUp() public {
        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);
        user = makeAddr("user");
        user2 = makeAddr("user2");

        // Set tx.origin to owner for deployment
        vm.startPrank(owner, owner);  // second parameter sets tx.origin
        
        // Deploy contracts
        buzz = new Buzz();
        token = new MockERC20();
        nft = new MockERC721();
        multiToken = new MockERC1155();
        vm.stopPrank();
        
        // Fund users with ETH
        vm.deal(user, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(owner, 100 ether);
    }

    function test_Ownership() public {
        // Initial owner should be the deployer
        assertEq(buzz.owner(), owner);

        // New owner
        address newOwner = makeAddr("newOwner");

        // Only owner can transfer ownership
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        buzz.transferOwnership(newOwner);

        // Owner can transfer ownership
        vm.prank(owner, owner);  // Set both msg.sender and tx.origin
        buzz.transferOwnership(newOwner);
        assertEq(buzz.owner(), newOwner);

        // Old owner can no longer transfer ownership
        vm.prank(owner, owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        buzz.transferOwnership(user);

        // New owner can transfer ownership
        vm.prank(newOwner, newOwner);
        buzz.transferOwnership(user);
        assertEq(buzz.owner(), user);
    }

    function test_RenounceOwnership() public {
        // Only owner can renounce ownership
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        buzz.renounceOwnership();

        // Owner can renounce ownership
        vm.prank(owner, owner);
        buzz.renounceOwnership();
        assertEq(buzz.owner(), address(0));

        // After renouncing, no one can transfer ownership
        vm.prank(owner, owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        buzz.transferOwnership(user);
    }

    function test_GetNonce() public {
        // Initial nonce should be 0
        uint256 referenceId1 = 1;
        uint256 referenceId2 = 2;
        assertEq(buzz.getNonce(referenceId1), 0);
        assertEq(buzz.getNonce(referenceId2), 0);

        // Setup withdrawal to increment nonce
        vm.deal(address(buzz), 5 ether);
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;

        // Create signature for first withdrawal
        bytes32 messageHash = keccak256(abi.encode(tokens, amounts, user, buzz.getNonce(referenceId1), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute withdrawal with referenceId1
        vm.prank(user);
        buzz.withdraw(tokens, amounts, referenceId1, user, expirationBlock, signature);

        // Nonce should be incremented for referenceId1 but not referenceId2
        assertEq(buzz.getNonce(referenceId1), 1);
        assertEq(buzz.getNonce(referenceId2), 0);

        // Create signature for second withdrawal
        messageHash = keccak256(abi.encode(tokens, amounts, user2, buzz.getNonce(referenceId2), expirationBlock)).toEthSignedMessageHash();
        (v, r, s) = vm.sign(ownerPrivateKey, messageHash);
        signature = abi.encodePacked(r, s, v);

        // Execute withdrawal with referenceId2
        vm.prank(user2);
        buzz.withdraw(tokens, amounts, referenceId2, user2, expirationBlock, signature);

        // Both nonces should be incremented
        assertEq(buzz.getNonce(referenceId1), 1);
        assertEq(buzz.getNonce(referenceId2), 1);
    }

    function test_ReceiveERC20() public {
        vm.startPrank(owner, owner);
        token.transfer(address(buzz), 100 ether);
        vm.stopPrank();
        assertEq(token.balanceOf(address(buzz)), 100 ether);
    }

    function test_ReceiveERC721() public {
        vm.startPrank(owner, owner);
        nft.safeTransferFrom(owner, address(buzz), 1);
        vm.stopPrank();
        assertEq(nft.ownerOf(1), address(buzz));
    }

    function test_ReceiveERC1155() public {
        vm.startPrank(owner, owner);
        multiToken.safeTransferFrom(owner, address(buzz), 1, 50, "");
        vm.stopPrank();
        assertEq(multiToken.balanceOf(address(buzz), 1), 50);
    }

    function test_ReceiveNativeCoin() public {
        vm.deal(user, 10 ether);
        vm.prank(user);
        (bool success,) = address(buzz).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(buzz).balance, 1 ether);
    }

    function test_RevertWhen_InvalidWithdrawalData() public {
        address[] memory tokens = new address[](2);
        uint256[] memory amounts = new uint256[](1);
        uint256 referenceId = 1;
        vm.expectRevert(abi.encodeWithSignature("InvalidWithdrawalData()"));
        buzz.withdraw(tokens, amounts, referenceId, user, block.number + 100, "");
    }

    function test_RevertWhen_Expired() public {
        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        uint256 referenceId = 1;
        vm.expectRevert(abi.encodeWithSignature("WithdrawalExpired()"));
        buzz.withdraw(tokens, amounts, referenceId, user, block.number - 1, "");
    }

    function test_RevertWhen_InvalidSignature() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;
        uint256 referenceId = 1;

        bytes32 messageHash = keccak256(abi.encode(tokens, amounts, user, buzz.getNonce(referenceId), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, messageHash); // Using wrong private key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSignature("InvalidSignature()"));
        buzz.withdraw(tokens, amounts, referenceId, user, expirationBlock, signature);
    }

    function test_RevertWhen_InsufficientBalance() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;
        uint256 referenceId = 1;

        bytes32 messageHash = keccak256(abi.encode(tokens, amounts, user, buzz.getNonce(referenceId), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSignature("TransferFailed()"));
        buzz.withdraw(tokens, amounts, referenceId, user, expirationBlock, signature);
    }

    function test_WithdrawNativeCoin() public {
        // Setup
        vm.deal(address(buzz), 5 ether);
        uint256 initialBalance = user.balance;

        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;
        uint256 referenceId = 1;

        bytes32 messageHash = keccak256(abi.encode(tokens, amounts, user, buzz.getNonce(referenceId), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        buzz.withdraw(tokens, amounts, referenceId, user, expirationBlock, signature);

        assertEq(user.balance, initialBalance + 1 ether);
        assertEq(address(buzz).balance, 4 ether);
    }

    function test_WithdrawERC20() public {
        // Setup
        vm.startPrank(owner, owner);
        token.transfer(address(buzz), 100 ether);
        vm.stopPrank();

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50 ether;

        uint256 expirationBlock = block.number + 100;
        uint256 referenceId = 1;

        bytes32 messageHash = keccak256(abi.encode(tokens, amounts, user, buzz.getNonce(referenceId), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        buzz.withdraw(tokens, amounts, referenceId, user, expirationBlock, signature);

        assertEq(token.balanceOf(user), 50 ether);
        assertEq(token.balanceOf(address(buzz)), 50 ether);
    }

    function test_WithdrawERC721() public {
        // Setup
        vm.startPrank(owner, owner);
        nft.safeTransferFrom(owner, address(buzz), 1);
        vm.stopPrank();

        address[] memory tokens = new address[](1);
        tokens[0] = address(nft);
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = 1;

        uint256 expirationBlock = block.number + 100;
        uint256 referenceId = 1;

        bytes32 messageHash = keccak256(abi.encode("ERC721", tokens, tokenIds, user, buzz.getNonce(referenceId), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        buzz.withdrawERC721(tokens, tokenIds, referenceId, user, expirationBlock, signature);

        assertEq(nft.ownerOf(1), user);
    }

    function test_WithdrawERC1155() public {
        // Setup
        vm.startPrank(owner, owner);
        multiToken.safeTransferFrom(owner, address(buzz), 1, 50, "");
        vm.stopPrank();

        address[] memory tokens = new address[](1);
        tokens[0] = address(multiToken);
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 25;

        uint256 expirationBlock = block.number + 100;
        uint256 referenceId = 1;

        bytes32 messageHash = keccak256(abi.encode("ERC1155", tokens, ids, amounts, user, buzz.getNonce(referenceId), expirationBlock)).toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(user);
        buzz.withdrawERC1155(tokens, ids, amounts, referenceId, user, expirationBlock, signature);

        assertEq(multiToken.balanceOf(user, 1), 25);
        assertEq(multiToken.balanceOf(address(buzz), 1), 25);
    }
}
