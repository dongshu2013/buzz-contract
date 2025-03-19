## Foundry

**Foundry is a blazing fast, portable and modular toolkit for Ethereum application development written in Rust.**

Foundry consists of:

-   **Forge**: Ethereum testing framework (like Truffle, Hardhat and DappTools).
-   **Cast**: Swiss army knife for interacting with EVM smart contracts, sending transactions and getting chain data.
-   **Anvil**: Local Ethereum node, akin to Ganache, Hardhat Network.
-   **Chisel**: Fast, utilitarian, and verbose solidity REPL.

## Buzz Contract

A simple message storage smart contract with owner-based access control built using Foundry.

## Features

- Message storage and updates
- Owner-based access control
- Event emission for message updates
- Comprehensive test coverage

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation.html)

### Installation

1. Clone the repository
2. Install dependencies:
```shell
forge install
```

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Format

```shell
$ forge fmt
```

### Gas Snapshots

```shell
$ forge snapshot
```

### Anvil

```shell
$ anvil
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

### Cast

```shell
$ cast <subcommand>
```

### Help

```shell
$ forge --help
$ anvil --help
$ cast --help
```

## Development

### Local Development

Start a local node:
```shell
$ anvil
```

### Deployment

1. Set up your environment variables:
```shell
export PRIVATE_KEY=your_private_key
```

2. Deploy the contract:
```shell
$ forge script script/Buzz.s.sol:BuzzScript --rpc-url <your_rpc_url> --broadcast
```

## Documentation

For more information about Foundry:
https://book.getfoundry.sh/

## Contract Interface

### Functions

- `constructor(string memory _initialMessage)`: Deploys the contract with an initial message
- `updateMessage(string memory _newMessage)`: Updates the stored message (only owner)
- `message()`: Returns the current message
- `owner()`: Returns the contract owner's address

### Events

- `MessageUpdated(string newMessage)`: Emitted when the message is updated
