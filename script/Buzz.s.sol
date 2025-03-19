// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/Buzz.sol";
import "forge-std/console.sol";

contract BuzzScript is Script {
    address constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    bytes32 constant SALT = bytes32(uint256(1)); // Using salt 1

    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        address owner = vm.addr(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        // Get the initialization code with constructor arguments
        bytes memory creationCode = abi.encodePacked(
            type(Buzz).creationCode,
            abi.encode(owner) // Pass owner address to constructor
        );
        
        // Calculate the deterministic address
        address predictedAddress = vm.computeCreate2Address(
            SALT,
            keccak256(creationCode),
            DETERMINISTIC_DEPLOYER
        );
        
        console.log("Predicted deployment address:", predictedAddress);

        // Deploy using CREATE2
        bytes memory deployCode = abi.encodePacked(
            hex"602d8060093d393df3363d3d373d3d3d363d73",
            DETERMINISTIC_DEPLOYER,
            hex"5af43d82803e903d91602b57fd5bf3",
            abi.encodePacked(bytes32(SALT), creationCode)
        );

        // Deploy the contract
        address deployedAddress;
        assembly {
            deployedAddress := create(0, add(deployCode, 0x20), mload(deployCode))
        }
        require(deployedAddress != address(0), "Deployment failed");
        require(deployedAddress == predictedAddress, "Deployment address mismatch");

        console.log("Contract deployed at:", deployedAddress);
        console.log("Contract owner set to:", owner);

        vm.stopBroadcast();
    }
}
