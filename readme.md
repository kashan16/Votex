# Votex

Votex is a blockchain-based voting system implemented in C++. It leverages the OpenSSL library for cryptographic operations, providing a secure and transparent way to manage votes.

## Features

- **Blockchain Technology**: Ensures the integrity and immutability of voting data.
- **RSA Encryption**: Secures voter identity and vote data.
- **Digital Signatures**: Authenticates votes to prevent tampering.

## Requirements

- C++ compiler
- OpenSSL library

## Installation

1. **Clone the repository**
    ```bash
    git clone https://github.com/kashan16/Votex.git
    cd Votex
    ```

2. **Install OpenSSL**

    On Ubuntu:
    ```bash
    sudo apt-get update
    sudo apt-get install libssl-dev
    ```

    On MacOS using Homebrew:
    ```bash
    brew install openssl
    ```

3. **Compile the project**
    ```bash
    g++ -o votex voting.cpp -lssl -lcrypto
    ```

## Usage

1. **Run the executable**
    ```bash
    ./votex
    ```

2. **Example output**
    ```
    Vote cast successfully!
    Blockchain is valid.
    ```

## Project Structure

- `voting.cpp`: Main source file containing the blockchain, cryptographic functions, and voting logic.

## Functions

- **generateKeyPair**: Generates RSA public and private keys.
- **signMessage**: Signs a message using a private key.
- **verifySignature**: Verifies a signed message using a public key.
- **calculateHash**: Computes the SHA-256 hash of a block.
- **castVote**: Creates and adds a new vote transaction to the blockchain.
- **isChainValid**: Checks the validity of the blockchain.

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Commit your changes.
5. Push to the branch.
6. Open a pull request.

## Author

- Kashan

## Acknowledgements

- OpenSSL for providing the cryptographic library.
