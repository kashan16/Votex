#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <ctime>
#include <stdexcept>
using namespace std;

struct Transaction {
    string voterID;
    string candidate;
    string signature;
};

struct Block {
    int index;
    vector<Transaction> transactions;
    string previousHash;
    string hash;
    time_t timestamp;
    int nonce;
};

string calculateHash(const Block& block) {
    stringstream ss;
    ss << block.index << block.previousHash << block.timestamp << block.nonce;

    for(const auto& tx : block.transactions) {
        ss << tx.voterID << tx.candidate <<tx.signature;
    }

    string data = ss.str();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)&data[0] , data.size() , hash);

    stringstream hashString;

    for(int i = 0 ; i < SHA256_DIGEST_LENGTH ; ++i) {
        hashString << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return hashString.str();
}

void handleOpenSSLErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void generateKeyPair(std::string& publicKey, std::string& privateKey) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleOpenSSLErrors();

    if (EVP_PKEY_keygen_init(ctx) <= 0) handleOpenSSLErrors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleOpenSSLErrors();

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleOpenSSLErrors();

    EVP_PKEY_CTX_free(ctx);

    // Save private key
    BIO *bp_private = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bp_private, pkey, NULL, NULL, 0, NULL, NULL)) handleOpenSSLErrors();

    int privateKeyLen = BIO_pending(bp_private);
    char *privateKeyCStr = new char[privateKeyLen + 1];
    BIO_read(bp_private, privateKeyCStr, privateKeyLen);
    privateKeyCStr[privateKeyLen] = '\0';
    privateKey = std::string(privateKeyCStr);

    // Save public key
    BIO *bp_public = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bp_public, pkey)) handleOpenSSLErrors();

    int publicKeyLen = BIO_pending(bp_public);
    char *publicKeyCStr = new char[publicKeyLen + 1];
    BIO_read(bp_public, publicKeyCStr, publicKeyLen);
    publicKeyCStr[publicKeyLen] = '\0';
    publicKey = std::string(publicKeyCStr);

    // Clean up
    EVP_PKEY_free(pkey);
    BIO_free_all(bp_private);
    BIO_free_all(bp_public);
    delete[] privateKeyCStr;
    delete[] publicKeyCStr;
}

string signMessage(const string& message , const string& privateKeyStr) {
    BIO *bio = BIO_new_mem_buf(privateKeyStr.c_str() , -1);
    return "";
}
