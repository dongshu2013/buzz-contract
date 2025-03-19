// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Buzz is IERC721Receiver, IERC1155Receiver, Ownable {
    using ECDSA for bytes32;

    mapping(address => uint256) public nonces;
    
    event WithdrawalBatch(address[] tokens, address recipient, uint256[] amounts);
    event ERC721Received(address operator, address from, uint256 tokenId, bytes data);
    event ERC1155Received(address operator, address from, uint256 id, uint256 value, bytes data);
    event ERC1155BatchReceived(address operator, address from, uint256[] ids, uint256[] values, bytes data);

    error InvalidSignature();
    error TransferFailed();
    error InvalidWithdrawalData();
    error WithdrawalExpired();

    constructor() Ownable(tx.origin) {}

    receive() external payable {}

    fallback() external payable {}

    /**
     * @dev Returns the current nonce for a recipient. This nonce is used to prevent replay attacks
     * and must be included in the signature for withdrawals.
     * @param recipient The address to get the nonce for
     * @return The current nonce for the recipient
     */
    function getNonce(address recipient) external view returns (uint256) {
        return nonces[recipient];
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

    function withdraw(
        address[] calldata tokens,
        uint256[] calldata amounts,
        address recipient,
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
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode(tokens, amounts, recipient, nonces[recipient], expirationBlock))
            )
        );
        
        if (messageHash.recover(signature) != owner()) {
            revert InvalidSignature();
        }

        nonces[recipient]++;

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

        emit WithdrawalBatch(tokens, recipient, amounts);
    }

    // For ERC721 withdrawals
    function withdrawERC721(
        address[] calldata tokens,
        uint256[] calldata tokenIds,
        address recipient,
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

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode("ERC721", tokens, tokenIds, recipient, nonces[recipient], expirationBlock))
            )
        );
        
        if (messageHash.recover(signature) != owner()) {
            revert InvalidSignature();
        }

        nonces[recipient]++;

        for (uint256 i = 0; i < tokens.length; i++) {
            IERC721(tokens[i]).safeTransferFrom(address(this), recipient, tokenIds[i]);
        }
    }

    // For ERC1155 withdrawals
    function withdrawERC1155(
        address[] calldata tokens,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        address recipient,
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

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encode("ERC1155", tokens, ids, amounts, recipient, nonces[recipient], expirationBlock))
            )
        );
        
        if (messageHash.recover(signature) != owner()) {
            revert InvalidSignature();
        }

        nonces[recipient]++;

        for (uint256 i = 0; i < tokens.length; i++) {
            IERC1155(tokens[i]).safeTransferFrom(
                address(this),
                recipient,
                ids[i],
                amounts[i],
                ""
            );
        }
    }
}
