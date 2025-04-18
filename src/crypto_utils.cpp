#include "crypto_utils.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <vector>
#include <stdexcept>
#include <sstream>
#include <cstring>
#include <iostream>

using namespace std;


string aes_encrypt(const string &plaintext, const unsigned char *key, const unsigned char *iv) {
    const string tag_prefix = "GCM";
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw runtime_error("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1)
        throw runtime_error("EVP_EncryptInit_ex failed");

    vector<unsigned char> ciphertext(plaintext.size());
    int len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1)
        throw runtime_error("EVP_EncryptUpdate failed");

    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        throw runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        throw runtime_error("EVP_CIPHER_CTX_ctrl (get tag) failed");

    EVP_CIPHER_CTX_free(ctx);

    string final_result = tag_prefix;
    final_result += string(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    final_result += string(reinterpret_cast<char*>(tag), 16);
    return final_result;
}



string aes_decrypt(const string &ciphertext, const unsigned char *key, const unsigned char *iv) {
    if (ciphertext.size() < 3)
        throw runtime_error("Invalid ciphertext length");

    string mode_tag = ciphertext.substr(0, 3);
    string actual_cipher = ciphertext.substr(3);

    if (actual_cipher.size() < 16)
        throw runtime_error("Ciphertext too short for GCM");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1)
        throw runtime_error("EVP_DecryptInit_ex failed");

    int ciphertext_len = actual_cipher.size() - 16;
    auto ciphertext_data = reinterpret_cast<const unsigned char*>(actual_cipher.data());
    auto tag = reinterpret_cast<const unsigned char*>(actual_cipher.data() + ciphertext_len);

    vector<unsigned char> plaintext(ciphertext_len);
    int len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext_data, ciphertext_len) != 1)
        throw runtime_error("EVP_DecryptUpdate failed");
    
    vector<unsigned char> tag_vec(tag, tag + 16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_vec.data()) != 1)
        throw runtime_error("EVP_CIPHER_CTX_ctrl (set tag) failed");

    int plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptFinal_ex failed (authentication failed)");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}


bool generate_aes_key_iv(unsigned char *key, unsigned char *iv) {
    return (RAND_bytes(key, AES_KEYLEN) == 1 && RAND_bytes(iv, AES_IVLEN) == 1);
}

string rsa_encrypt(RSA *rsa, const string &data) {
    int rsa_size = RSA_size(rsa);
    vector<unsigned char> encrypted(rsa_size);
    int len = RSA_public_encrypt(data.size(), reinterpret_cast<const unsigned char*>(data.data()), encrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1)
        throw runtime_error("RSA_public_encrypt failed");
    return string(reinterpret_cast<char*>(encrypted.data()), len);
}

string rsa_decrypt(RSA *rsa, const string &data) {
    int rsa_size = RSA_size(rsa);
    vector<unsigned char> decrypted(rsa_size);
    int len = RSA_private_decrypt(data.size(), reinterpret_cast<const unsigned char*>(data.data()), decrypted.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    if (len == -1)
        throw runtime_error("RSA_private_decrypt failed");
    return string(reinterpret_cast<char*>(decrypted.data()), len);
}

RSA* load_public_key(const string &path) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp)
        return nullptr;
    RSA *rsa = PEM_read_RSA_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return rsa;
}

RSA* load_private_key(const string &path, const string &passphrase) {
    FILE *fp = fopen(path.c_str(), "r");
    if (!fp)
        return nullptr;
    RSA *rsa = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, const_cast<char*>(passphrase.c_str()));
    fclose(fp);
    return rsa;
}

bool generate_rsa_keypair(const string &privateKeyPath, const string &publicKeyPath, const string &passphrase) {
    int bits = 2048;
    RSA *rsa = RSA_generate_key(bits, RSA_F4, nullptr, nullptr);
    if (!rsa)
        return false;
    FILE *fp = fopen(privateKeyPath.c_str(), "w");
    if (!fp) {
        RSA_free(rsa);
        return false;
    }
    // Write the private key, encrypted with AES-256-CBC using the given passphrase.
    if (!PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), nullptr, 0, nullptr, const_cast<char*>(passphrase.c_str()))) {
        fclose(fp);
        RSA_free(rsa);
        return false;
    }
    fclose(fp);
    fp = fopen(publicKeyPath.c_str(), "w");
    if (!fp) {
        RSA_free(rsa);
        return false;
    }
    if (!PEM_write_RSA_PUBKEY(fp, rsa)) {
        fclose(fp);
        RSA_free(rsa);
        return false;
    }
    fclose(fp);
    RSA_free(rsa);
    return true;
}

// Generate a random passphrase (here 16 bytes represented in hex).
string generateRandomPassphrase() {
    unsigned char buf[16];
    if(RAND_bytes(buf, sizeof(buf)) != 1)
        return "defaultpass"; // fallback if RAND_bytes fails
    ostringstream oss;
    for (int i = 0; i < 16; i++) {
        oss << hex << ((int)buf[i]);
    }
    return oss.str();
}

// Challenge-response authentication: encrypt a test string with the public key and decrypt it with the private key.
bool authenticateUser(const string &username,
                      const string &publicKeyPath,
                      const string &privateKeyPath,
                      const string &passphrase) {
    const string testStr = "test_challenge";

    // Load public key from the given file.
    RSA* rsa_pub = load_public_key(publicKeyPath);
    if (!rsa_pub) {
        cerr << "Failed to load public key from " << publicKeyPath << "\n";
        return false;
    }

    string encrypted;
    try {
        encrypted = rsa_encrypt(rsa_pub, testStr);
    } catch (const exception &ex) {
        cerr << "RSA encryption failed: " << ex.what() << "\n";
        RSA_free(rsa_pub);
        return false;
    }
    RSA_free(rsa_pub);

    // Load private key from the protected keyfiles folder.
    RSA* rsa_priv = load_private_key(privateKeyPath, passphrase);
    if (!rsa_priv) {
        cerr << "Failed to load private key from " << privateKeyPath << "\n";
        return false;
    }

    string decrypted;
    try {
        decrypted = rsa_decrypt(rsa_priv, encrypted);
    } catch (const exception &ex) {
        cerr << "RSA decryption failed: " << ex.what() << "\n";
        RSA_free(rsa_priv);
        return false;
    }
    RSA_free(rsa_priv);

    return (decrypted == testStr);
}

// Derive a 32-byte key from a password using SHA-256 (simple example; PBKDF2 is preferred).
string deriveKeyFromPassword(const string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash);
    return string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

bool verifyKeyPair(const string &publicKeyPath,
                   const string &privateKeyPath,
                   const string &passphrase) {
    const string testStr = "verify_keypair";
    RSA* rsaPub = load_public_key(publicKeyPath);
    if (!rsaPub) {
        cerr << "Failed to load public key from " << publicKeyPath << endl;
        return false;
    }
    string encrypted;
    try {
        encrypted = rsa_encrypt(rsaPub, testStr);
    } catch (const exception &ex) {
        cerr << "Encryption failed: " << ex.what() << endl;
        RSA_free(rsaPub);
        return false;
    }
    RSA_free(rsaPub);

    RSA* rsaPriv = load_private_key(privateKeyPath, passphrase);
    if (!rsaPriv) {
        cerr << "Failed to load private key from " << privateKeyPath << endl;
        return false;
    }
    string decrypted;
    try {
        decrypted = rsa_decrypt(rsaPriv, encrypted);
    } catch (const exception &ex) {
        cerr << "Decryption failed: " << ex.what() << endl;
        RSA_free(rsaPriv);
        return false;
    }
    RSA_free(rsaPriv);

    return (decrypted == testStr);
}
