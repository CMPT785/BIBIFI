#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <string>

#include <openssl/rsa.h>
#include <openssl/sha.h>

using namespace std;

// AES constants
const int AES_KEYLEN = 32; // 256-bit key
const int AES_IVLEN  = 16; // 128-bit IV

// AES encryption/decryption
string aes_encrypt(const string &plaintext, const unsigned char *key, const unsigned char *iv);
string aes_decrypt(const string &ciphertext, const unsigned char *key, const unsigned char *iv);
bool generate_aes_key_iv(unsigned char *key, unsigned char *iv);

// RSA functions
string rsa_encrypt(RSA *rsa, const string &data);
string rsa_decrypt(RSA *rsa, const string &data);
RSA* load_public_key(const string &path);
RSA* load_private_key(const string &path, const string &passphrase);
bool generate_rsa_keypair(const string &privateKeyPath, const string &publicKeyPath, const string &passphrase);

// Utility functions
string generateRandomPassphrase();
bool authenticateUser(const string &username,
                      const string &publicKeyPath,
                      const string &privateKeyPath,
                      const string &passphrase);
string deriveKeyFromPassword(const string &password);
bool verifyKeyPair(const string &publicKeyPath,
                   const string &privateKeyPath,
                   const string &passphrase);

#endif // CRYPTO_UTILS_H
