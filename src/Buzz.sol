// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Buzz is IERC721Receiver, IERC1155Receiver, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address public validator;
    mapping(uint256 => uint256) public nonces;

    event Deposit(uint256 indexed referenceId, address indexed token, uint256 tokenAmount, uint256 valueAmount);
    event WithdrawalBatch(uint256 indexed requestId, uint256 indexed nonce, address indexed recipient, address[] tokens, uint256[] amounts);
    event WithdrawalERC721Batch(uint256 requestId, uint256 nonce, address recipient, address[] tokens, uint256[] tokenIds);
    event WithdrawalERC1155Batch(uint256 requestId, uint256 nonce, address recipient, address[] tokens, uint256[] ids, uint256[] amounts);

    event ERC721Received(address operator, address from, uint256 tokenId, bytes data);
    event ERC1155Received(address operator, address from, uint256 id, uint256 value, bytes data);
    event ERC1155BatchReceived(address operator, address from, uint256[] ids, uint256[] values, bytes data);

    event ValidatorUpdated(address indexed newValidator, address indexed oldValidator);

    error InvalidSignature();
    error TransferFailed();
    error InvalidWithdrawalData();
    error WithdrawalExpired();
    error InvalidValidator();

    constructor() Ownable(tx.origin) {}

    receive() external payable {}

    fallback() external payable {}

    function getNonce(uint256 referenceId) external view returns (uint256) {
        return nonces[referenceId];
    }

    function deposit(uint256 referenceId, address token, uint256 tokenAmount) external payable {
        if (token != address(0)) {
            IERC20(token).transferFrom(msg.sender, address(this), tokenAmount);
        }
        emit Deposit(referenceId, token, tokenAmount, msg.value);
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external override returns (bytes4) {
        emit ERC721Received(operator, from, tokenId, data);
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external override returns (bytes4) {
        emit ERC1155Received(operator, from, id, value, data);
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external override returns (bytes4) {
        emit ERC1155BatchReceived(operator, from, ids, values, data);
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return
            interfaceId == type(IERC721Receiver).interfaceId ||
            interfaceId == type(IERC1155Receiver).interfaceId;
    }

    function setValidator(address newValidator) external onlyOwner {
        if (newValidator == address(0)) revert InvalidValidator();
        address oldValidator = validator;
        validator = newValidator;
        emit ValidatorUpdated(newValidator, oldValidator);
    }

    function withdraw(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256 referenceId,
        address recipient,
        uint256 requestId,
        uint256 expirationBlock,
        bytes calldata signature
    ) external {
        // Check expiration
        if (block.number > expirationBlock) {
            revert WithdrawalExpired();
        }

        // Validate input arrays
        if (tokens.length != amounts.length || tokens.length == 0) {
            revert InvalidWithdrawalData();
        }

        // Verify signature
        uint256 nonce = nonces[referenceId];
        bytes32 hash = keccak256(abi.encode(tokens, amounts, recipient, requestId, nonce, expirationBlock));
        bytes32 messageHash = hash.toEthSignedMessageHash();
        
        if (messageHash.recover(signature) != validator) {
            revert InvalidSignature();
        }

        nonces[referenceId]++;

        // Process withdrawals
        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 amount = amounts[i];

            if (token == address(0)) {
                // Native token transfer
                (bool success, ) = recipient.call{value: amount}("");
                if (!success) revert TransferFailed();
            } else {
                // ERC20 token transfer
                bool success = IERC20(token).transfer(recipient, amount);
                if (!success) revert TransferFailed();
            }
        }

        emit WithdrawalBatch(requestId, nonce, recipient, tokens, amounts);
    }

    // For ERC721 withdrawals
    function withdrawERC721(
        address[] calldata tokens,
        uint256[] calldata tokenIds,
        uint256 referenceId,
        address recipient,
        uint256 requestId,
        uint256 expirationBlock,
        bytes calldata signature
    ) external {
        // Check expiration
        if (block.number > expirationBlock) {
            revert WithdrawalExpired();
        }

        if (tokens.length != tokenIds.length || tokens.length == 0) {
            revert InvalidWithdrawalData();
        }

        uint256 nonce = nonces[referenceId];
        bytes32 hash = keccak256(abi.encode("ERC721", tokens, tokenIds, recipient, requestId, nonce, expirationBlock));
        bytes32 messageHash = hash.toEthSignedMessageHash();
        
        address signer = messageHash.recover(signature);
        if (signer != validator) {
            revert InvalidSignature();
        }

        nonces[referenceId]++;

        for (uint256 i = 0; i < tokens.length; i++) {
            IERC721(tokens[i]).safeTransferFrom(address(this), recipient, tokenIds[i]);
        }

        emit WithdrawalERC721Batch(requestId, nonce, recipient, tokens, tokenIds);
    }

    // For ERC1155 withdrawals
    function withdrawERC1155(
        address[] calldata tokens,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        uint256 referenceId,
        address recipient,
        uint256 requestId,
        uint256 expirationBlock,
        bytes calldata signature
    ) external {
        // Check expiration
        if (block.number > expirationBlock) {
            revert WithdrawalExpired();
        }

        if (tokens.length != ids.length || tokens.length != amounts.length || tokens.length == 0) {
            revert InvalidWithdrawalData();
        }

        uint256 nonce = nonces[referenceId];
        bytes32 hash = keccak256(abi.encode("ERC1155", tokens, ids, amounts, recipient, requestId, nonce, expirationBlock));
        bytes32 messageHash = hash.toEthSignedMessageHash();
        
        address signer = messageHash.recover(signature);
        if (signer != validator) {
            revert InvalidSignature();
        }

        nonces[referenceId]++;

        for (uint256 i = 0; i < tokens.length; i++) {
            IERC1155(tokens[i]).safeTransferFrom(
                address(this),
                recipient,
                ids[i],
                amounts[i],
                ""
            );
        }

        emit WithdrawalERC1155Batch(requestId, nonce, recipient, tokens, ids, amounts);
    }
}
