// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/Buzz.sol";
import "forge-std/console.sol";

contract BuzzScript is Script {
    address constant DETERMINISTIC_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function setUp() public {}

    function run() public {
        uint256 deployerPrivateKey = uint256(vm.envBytes32("PRIVATE_KEY"));
        vm.startBroadcast(deployerPrivateKey);

        // Get the initialization code
        bytes memory creationCode = type(Buzz).creationCode;

        // Use a fixed salt for deterministic deployment across all chains
        bytes32 salt = keccak256(bytes("buzz_contract_v1"));

        // Calculate the deterministic address
        address predictedAddress = vm.computeCreate2Address(
            salt,
            keccak256(creationCode),
            DETERMINISTIC_DEPLOYER
        );
        console.log("Predicted deployment address:", predictedAddress);

        // Check if contract is already deployed
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(predictedAddress)
        }

        if (codeSize == 0) {
            console.log("Deploying new contract...");

            // Format the calldata for the CREATE2 deployer
            // The calldata should be: <32 bytes salt><initialization code>
            bytes memory deployData = bytes.concat(salt, creationCode);

            // Send transaction directly to the CREATE2 deployer
            (bool success,) = DETERMINISTIC_DEPLOYER.call{gas: 3000000}(deployData);
            require(success, "Deployment failed");

            // Verify deployment
            assembly {
                codeSize := extcodesize(predictedAddress)
            }
            require(codeSize > 0, "Deployment verification failed");

            console.log("Contract deployed at:", predictedAddress);
            address owner = Buzz(payable(predictedAddress)).owner();
            console.log("Contract owner set to:", owner);
        } else {
            console.log("Contract already deployed at:", predictedAddress);
            console.log("Current owner:", Buzz(payable(predictedAddress)).owner());
        }

        vm.stopBroadcast();
    }
}
