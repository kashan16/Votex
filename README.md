# Votex - Blockchain-Based Secure Voting System

Votex is a secure, transparent, and tamper-proof voting system built on blockchain technology. It leverages cryptographic principles to ensure vote integrity, voter authentication, and transparent election processes.

## Features

- **Blockchain Immutability**: Every vote is permanently recorded in an immutable blockchain
- **Cryptographic Security**: RSA-2048 encryption and SHA-256 hashing for maximum security
- **Digital Signatures**: Each vote is cryptographically signed to prevent forgery
- **Proof of Work**: Mining mechanism prevents spam and ensures network consensus
- **Transparent Auditing**: Complete transaction history available for verification
- **Voter Authentication**: Registered voter system prevents duplicate voting

## Architecture

### Core Components

1. **Cryptographic Engine**
   - RSA key pair generation (2048-bit)
   - Digital signature creation and verification
   - SHA-256 hashing for block integrity

2. **Blockchain Implementation**
   - Proof of Work consensus mechanism
   - Configurable mining difficulty
   - Genesis block initialization
   - Chain validation and integrity checks

3. **Voting System**
   - Voter registration and authentication
   - Secure vote casting with digital signatures
   - Transaction batching into blocks
   - Real-time vote verification

## Requirements

- **C++17** compatible compiler (GCC, Clang, or MSVC)
- **OpenSSL 1.1.1+** development libraries

### Installing Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

**CentOS/RHEL:**
```bash
sudo yum groupinstall 'Development Tools'
sudo yum install openssl-devel
```

**macOS:**
```bash
brew install openssl
```

**Windows (vcpkg):**
```bash
vcpkg install openssl
```

## Installation

### Building from Source

```bash
# Clone the repository
git clone https://github.com/kashan16/Votex.git
cd Votex

# Compile the project
g++ -o votex main.cpp -lssl -lcrypto -std=c++17

# Or with clang
clang++ -o votex main.cpp -lssl -lcrypto -std=c++17
```

### CMake Build (Recommended)

```bash
mkdir build && cd build
cmake ..
make
```

## Usage

### Basic Operation

```cpp
#include "Votex.h"

int main() {
    // Initialize voting system with mining difficulty
    VotingSystem votingSystem(4); // Difficulty level 4
    
    // Register voters
    votingSystem.registerVoter("Alice");
    votingSystem.registerVoter("Bob");
    
    // Generate cryptographic keys for voters
    std::string publicKey, privateKey;
    generateKeyPair(publicKey, privateKey);
    
    // Cast votes
    votingSystem.castVote("Alice", "CandidateX", privateKey);
    votingSystem.castVote("Bob", "CandidateY", privateKey);
    
    // Verify and display results
    votingSystem.verifyVotes();
    
    return 0;
}
```

### Advanced Configuration

```cpp
// Custom block size (number of transactions per block)
votingSystem.setBlockSize(5);

// Adjust mining difficulty based on network requirements
VotingSystem highSecuritySystem(6); // Higher difficulty = more security
```

## API Reference

### Core Functions

#### Key Management
```cpp
// Generate RSA key pair
void generateKeyPair(std::string& publicKey, std::string& privateKey);

// Sign a message with private key
std::string signMessage(const std::string& message, const std::string& privateKey);

// Verify signature with public key
bool verifyMessage(const std::string& message, const std::string& signature, 
                   const std::string& publicKey);
```

#### Voting Operations
```cpp
// Register a voter
void registerVoter(const std::string& voterID);

// Cast a vote
void castVote(const std::string& voterID, const std::string& candidate, 
              const std::string& privateKey);

// Verify all votes in the blockchain
void verifyVotes() const;
```

### Data Structures

#### Transaction
```cpp
struct Transaction {
    std::string voterID;      // Unique voter identifier
    std::string candidate;    // Candidate being voted for
    std::string signature;    // Cryptographic signature
    time_t timestamp;         // When the vote was cast
};
```

#### Block
```cpp
struct Block {
    int index;               // Block position in chain
    std::vector<Transaction> transactions; // Vote transactions
    std::string previousHash; // Hash of previous block
    std::string hash;        // Current block hash
    time_t timestamp;        // Block creation time
    int nonce;              // Proof of work nonce
};
```

## Security Features

### Cryptographic Guarantees
- **Vote Integrity**: Each vote is cryptographically signed and cannot be altered
- **Voter Privacy**: Voter identities are protected while maintaining auditability
- **Chain Integrity**: Blockchain hashing ensures historical votes cannot be modified
- **Double Spending Prevention**: Registered voter system prevents multiple votes

### Consensus Mechanism
- **Proof of Work**: Blocks require computational work to mine, preventing spam
- **Configurable Difficulty**: Adjustable mining difficulty based on network needs
- **Chain Validation**: Automatic verification of blockchain integrity

## Example Output

```
Block mined: 0000a1b2c3d4e5f6...
Vote cast by Alice for CandidateX
Vote cast by Bob for CandidateY

Blockchain Verification:
Block #1, Hash: 0000a1b2c3d4e5f6...
  Voter: Alice, Voted for: CandidateX
  Voter: Bob, Voted for: CandidateY
```

## Performance Considerations

- **Block Size**: Adjust based on expected transaction volume
- **Mining Difficulty**: Higher values increase security but reduce performance
- **Memory Usage**: Linear growth with number of transactions
- **CPU Usage**: Mining process is CPU-intensive during block creation

## Extending the System

### Adding New Features

1. **Multiple Elections**:
```cpp
class Election {
    std::string electionId;
    std::vector<std::string> candidates;
    VotingSystem votingSystem;
};
```

2. **Network Distribution**:
```cpp
class NetworkNode {
    void broadcastBlock(const Block& block);
    void receiveBlock(const Block& block);
};
```

3. **Advanced Cryptography**:
```cpp
// Add support for elliptic curve cryptography
void generateECKeyPair(std::string& publicKey, std::string& privateKey);
```

## Testing

### Unit Tests
```bash
# Run basic functionality tests
./votex --test

# Run security validation
./votex --security-test
```

### Integration Testing
```cpp
// Example test case
void testVoteIntegrity() {
    VotingSystem vs(2);
    vs.registerVoter("TestVoter");
    
    std::string pub, priv;
    generateKeyPair(pub, priv);
    vs.castVote("TestVoter", "TestCandidate", priv);
    
    assert(vs.verifyVotes() == true);
}
```

## Troubleshooting

### Common Issues

1. **OpenSSL Not Found**:
   ```bash
   export PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig
   ```

2. **Compilation Errors**:
   Ensure C++17 support is enabled and OpenSSL development libraries are installed.

3. **Memory Issues**:
   The system is designed for moderate transaction volumes. For large-scale deployments, consider implementing memory management optimizations.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/kashan16/Votex.git
cd Votex
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Mohd Kashan Yunus** - [@kashan16](https://github.com/kashan16)

## Acknowledgements

- **OpenSSL Project** for robust cryptographic libraries
- **Bitcoin** for pioneering blockchain technology concepts
- **Academic Research** in cryptographic voting systems and blockchain applications

---

<div align="center">
  <strong>Building Trust in Democratic Processes Through Technology</strong>
</div>
