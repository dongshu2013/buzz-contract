// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Buzz} from "../src/Buzz.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

// Mock tokens for testing
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
        
        // Deploy contracts
        vm.startPrank(owner);
        buzz = new Buzz(owner);
        token = new MockERC20();
        nft = new MockERC721();
        multiToken = new MockERC1155();
        vm.stopPrank();
        
        // Fund users with ETH
        vm.deal(user, 100 ether);
        vm.deal(user2, 100 ether);
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
        vm.prank(owner);
        buzz.transferOwnership(newOwner);
        assertEq(buzz.owner(), newOwner);

        // Old owner can no longer transfer ownership
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        buzz.transferOwnership(user);

        // New owner can transfer ownership
        vm.prank(newOwner);
        buzz.transferOwnership(user);
        assertEq(buzz.owner(), user);
    }

    function test_RenounceOwnership() public {
        // Only owner can renounce ownership
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", user));
        buzz.renounceOwnership();

        // Owner can renounce ownership
        vm.prank(owner);
        buzz.renounceOwnership();
        assertEq(buzz.owner(), address(0));

        // After renouncing, no one can transfer ownership
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", owner));
        buzz.transferOwnership(user);
    }

    function test_GetNonce() public {
        // Initial nonce should be 0
        assertEq(buzz.getNonce(user), 0);
        assertEq(buzz.getNonce(user2), 0);

        // Setup withdrawal to increment nonce
        vm.deal(address(buzz), 5 ether);
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;

        // Create signature for user1
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, buzz.getNonce(user), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute withdrawal for user1
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Nonce should be incremented for user1 but not user2
        assertEq(buzz.getNonce(user), 1);
        assertEq(buzz.getNonce(user2), 0);

        // Create signature for user2
        messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user2, buzz.getNonce(user2), expirationBlock))
            )
        );
        (v, r, s) = vm.sign(ownerPrivateKey, messageHash);
        signature = abi.encodePacked(r, s, v);

        // Execute withdrawal for user2
        vm.prank(user2);
        buzz.withdraw(tokens, amounts, user2, expirationBlock, signature);

        // Both nonces should be incremented
        assertEq(buzz.getNonce(user), 1);
        assertEq(buzz.getNonce(user2), 1);
    }

    function test_ReceiveNativeCoin() public {
        vm.prank(user);
        (bool success,) = address(buzz).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(buzz).balance, 1 ether);
    }

    function test_ReceiveERC20() public {
        vm.startPrank(owner);
        token.transfer(address(buzz), 100 ether);
        vm.stopPrank();
        assertEq(token.balanceOf(address(buzz)), 100 ether);
    }

    function test_ReceiveERC721() public {
        vm.startPrank(owner);
        nft.safeTransferFrom(owner, address(buzz), 1);
        vm.stopPrank();
        assertEq(nft.ownerOf(1), address(buzz));
    }

    function test_ReceiveERC1155() public {
        vm.startPrank(owner);
        multiToken.safeTransferFrom(owner, address(buzz), 1, 50, "");
        vm.stopPrank();
        assertEq(multiToken.balanceOf(address(buzz), 1), 50);
    }

    function test_WithdrawNativeCoin() public {
        // Setup
        vm.deal(address(buzz), 5 ether);
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;

        // Create signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Initial balances
        uint256 initialUserBalance = user.balance;
        uint256 initialContractBalance = address(buzz).balance;

        // Execute withdrawal
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Verify balances
        assertEq(user.balance, initialUserBalance + 1 ether);
        assertEq(address(buzz).balance, initialContractBalance - 1 ether);
        assertEq(buzz.nonces(user), 1);
    }

    function test_WithdrawERC20() public {
        // Setup
        vm.startPrank(owner);
        token.transfer(address(buzz), 100 ether);
        vm.stopPrank();

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 50 ether;

        uint256 expirationBlock = block.number + 100;

        // Create signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute withdrawal
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Verify balances
        assertEq(token.balanceOf(user), 50 ether);
        assertEq(token.balanceOf(address(buzz)), 50 ether);
        assertEq(buzz.nonces(user), 1);
    }

    function test_WithdrawERC721() public {
        // Setup
        vm.startPrank(owner);
        nft.safeTransferFrom(owner, address(buzz), 1);
        vm.stopPrank();

        address[] memory tokens = new address[](1);
        tokens[0] = address(nft);
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = 1;

        uint256 expirationBlock = block.number + 100;

        // Create signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode("ERC721", tokens, tokenIds, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute withdrawal
        vm.prank(user);
        buzz.withdrawERC721(tokens, tokenIds, user, expirationBlock, signature);

        // Verify ownership and nonce
        assertEq(nft.ownerOf(1), user);
        assertEq(buzz.nonces(user), 1);
    }

    function test_WithdrawERC1155() public {
        // Setup
        vm.startPrank(owner);
        multiToken.safeTransferFrom(owner, address(buzz), 1, 50, "");
        vm.stopPrank();

        address[] memory tokens = new address[](1);
        tokens[0] = address(multiToken);
        uint256[] memory ids = new uint256[](1);
        ids[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 30;

        uint256 expirationBlock = block.number + 100;

        // Create signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode("ERC1155", tokens, ids, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute withdrawal
        vm.prank(user);
        buzz.withdrawERC1155(tokens, ids, amounts, user, expirationBlock, signature);

        // Verify balances and nonce
        assertEq(multiToken.balanceOf(user, 1), 30);
        assertEq(multiToken.balanceOf(address(buzz), 1), 20);
        assertEq(buzz.nonces(user), 1);
    }

    function test_IndependentUserNonces() public {
        // Setup for both users
        vm.deal(address(buzz), 10 ether);

        // First user withdrawal
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;

        // Create signature for user1
        bytes32 messageHash1 = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPrivateKey, messageHash1);
        bytes memory signature1 = abi.encodePacked(r1, s1, v1);

        // Create signature for user2
        bytes32 messageHash2 = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user2, uint256(0), expirationBlock))
            )
        );
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPrivateKey, messageHash2);
        bytes memory signature2 = abi.encodePacked(r2, s2, v2);

        // Execute withdrawals
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature1);

        vm.prank(user2);
        buzz.withdraw(tokens, amounts, user2, expirationBlock, signature2);

        // Verify nonces are independent
        assertEq(buzz.nonces(user), 1);
        assertEq(buzz.nonces(user2), 1);
    }

    function test_RevertWhen_Expired() public {
        // Setup
        vm.deal(address(buzz), 5 ether);
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;

        // Create signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Move past expiration block
        vm.roll(expirationBlock + 1);

        // Expect revert
        vm.expectRevert(Buzz.WithdrawalExpired.selector);
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Verify nonce was not incremented
        assertEq(buzz.nonces(user), 0);
    }

    function test_RevertWhen_InvalidSignature() public {
        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1 ether;

        uint256 expirationBlock = block.number + 100;

        // Create invalid signature (wrong private key)
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xB0B, messageHash); // Different private key
        bytes memory signature = abi.encodePacked(r, s, v);

        // Expect revert
        vm.expectRevert(Buzz.InvalidSignature.selector);
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Verify nonce was not incremented
        assertEq(buzz.nonces(user), 0);
    }

    function test_RevertWhen_InvalidWithdrawalData() public {
        address[] memory tokens = new address[](1);
        uint256[] memory amounts = new uint256[](2); // Mismatched array lengths

        uint256 expirationBlock = block.number + 100;
        bytes memory signature = "0x00"; // Any signature

        vm.expectRevert(Buzz.InvalidWithdrawalData.selector);
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Verify nonce was not incremented
        assertEq(buzz.nonces(user), 0);
    }

    function test_RevertWhen_InsufficientBalance() public {
        // Try to withdraw more than contract has
        vm.deal(address(buzz), 1 ether);

        address[] memory tokens = new address[](1);
        tokens[0] = address(0);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 2 ether; // More than contract balance

        uint256 expirationBlock = block.number + 100;

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, user, uint256(0), expirationBlock))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(Buzz.TransferFailed.selector);
        vm.prank(user);
        buzz.withdraw(tokens, amounts, user, expirationBlock, signature);

        // Verify nonce was not incremented
        assertEq(buzz.nonces(user), 0);
    }
}
