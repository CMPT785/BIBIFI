#include "encrypted_fs.h"
#include "fs_utils.h"
#include "crypto_utils.h"
#include "user_metadata.h"
#include "shared_metadata.h"
#include "sharing_key_manager.h"

#include <iostream>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <string>

using namespace std;


// Write a file with encryption.
// The file format is: [4 bytes keyLen][4 bytes ivLen][encrypted AES key][encrypted IV][AES-encrypted file content]
bool encryptedWriteFile(const string &path, const string &plaintext, const string &ownerUsername, const string &ownerDerivedKey, const string &globalSharingKey) {
    // Load owner's public key (stored outside the filesystem as "<ownerUsername>_keyfile.pem").
    string publicKeyPath = "public_keys/" + ownerUsername + "_keyfile.pem";
    RSA* rsa = load_public_key(publicKeyPath);
    if (!rsa) {
        cerr << "Failed to load public key for " << ownerUsername << endl;
        return false;
    }
    // Generate random AES key and IV.
    unsigned char aes_key[AES_KEYLEN], aes_iv[AES_IVLEN];
    if (!generate_aes_key_iv(aes_key, aes_iv)) {
        RSA_free(rsa);
        return false;
    }
    // Encrypt plaintext with AES.
    string encryptedContent;
    try {
        encryptedContent = aes_encrypt(plaintext, aes_key, aes_iv);
    } catch (const exception &ex) {
        cerr << "AES encryption failed: " << ex.what() << endl;
        RSA_free(rsa);
        return false;
    }

    // Create the envelope: concatenate AES key and IV.
    string keyIV(reinterpret_cast<char*>(aes_key), AES_KEYLEN);
    keyIV.append(reinterpret_cast<char*>(aes_iv), AES_IVLEN);

    // explicit copy
    string clearIV = keyIV;

    // RSA-wrap the envelope for the owner.
    string envelope;
    try {
        envelope = rsa_encrypt(rsa, keyIV);
    } catch (const exception &ex) {
        cerr << "RSA encryption failed: " << ex.what() << endl;
        RSA_free(rsa);
        return false;
    }
    RSA_free(rsa);

    // Write the AES-encrypted file content.
    if (!writeFile(path, encryptedContent))
        return false;

    // Update the owner's metadata (stored in their encrypted envelope metadata file)
    // with the new envelope for this file.
    if (!updateUserEnvelopeEntry(ownerUsername, ownerDerivedKey, path, envelope)){
        cerr << "Warning: failed to update user access for file: " << path << endl;
        return false;
    }

    // Now update admin access
    // Call the function to re-wrap the clear keyIV for admin using the global sharing key.
    if (ownerUsername != "admin") {
        if (!updateAdminAccessForFile(ownerUsername, ownerDerivedKey, globalSharingKey, path, clearIV)) {
            cerr << "Warning: failed to update admin access for file: " << path << endl;
            return false;
        }
    }

    if (!updateRecursiveShare(ownerUsername, ownerDerivedKey, path, globalSharingKey, clearIV)) {
        cerr << "Recursive share update failed for file " << path << endl;
    }

    return true;
}


// Read and decrypt a file.
bool encryptedReadFile(const string &path, string &plaintext, const string &username, const string &passphrase, const string &derivedKey, const string &globalKey) {

    string encryptedContent;
    if (!readFile(path, encryptedContent))
        return false;

    string envelope;
    bool isShared = false;
    // First, try to get the envelope from the user's own metadata.
    if (!findUserEnvelope(username, path, derivedKey, envelope)) {
        // If not found, try the shared envelope.
        if (!findUserSharedEnvelope(username, path, globalKey, envelope)) {
            cerr << "No envelope found for " << username << " for file " << path << endl;
            return false;
        }
        isShared = true;
    }
    
    string keyIV;
    if (!isShared) {
        // For owner's envelope: use RSA decryption.
        string privateKeyPath = "filesystem/keyfiles/" + username + "_keyfile.pem";
        RSA* rsa = load_private_key(privateKeyPath, passphrase);
        if (!rsa) {
            cerr << "Failed to load private key for " << username << endl;
            return false;
        }
        try {
            keyIV = rsa_decrypt(rsa, envelope);
        } catch (const exception &ex) {
            cerr << "RSA decryption failed: " << ex.what() << endl;
            RSA_free(rsa);
            return false;
        }
        RSA_free(rsa);
    } else {
        // For shared envelope: the envelope is symmetrically encrypted using the global sharing key.
        if (envelope.size() < AES_IVLEN) {
            cerr << "Shared envelope is too short." << endl;
            return false;
        }
        string symIV = envelope.substr(0, AES_IVLEN);
        string symCiphertext = envelope.substr(AES_IVLEN);
        try {
            keyIV = aes_decrypt(symCiphertext,
                                reinterpret_cast<const unsigned char*>(globalKey.data()),
                                reinterpret_cast<const unsigned char*>(symIV.data()));
        } catch (const exception &ex) {
            cerr << "AES decryption of shared envelope failed: " << ex.what() << endl;
            return false;
        }
    }
    
    if (keyIV.size() != AES_KEYLEN + AES_IVLEN) {
        cerr << "Invalid key/IV length." << endl;
        return false;
    }
    const unsigned char *aes_key = reinterpret_cast<const unsigned char*>(keyIV.data());
    const unsigned char *aes_iv  = reinterpret_cast<const unsigned char*>(keyIV.data() + AES_KEYLEN);
    
    try {
        plaintext = aes_decrypt(encryptedContent, aes_key, aes_iv);
    } catch (const exception &ex) {
        cerr << "AES decryption failed: " << ex.what() << endl;
        return false;
    }
    return true;
}


// Unused: Reads and decrypts a global metadata file (like global_sharing.key or a shared_envelopes.enc file)
// using the global sharing key. Returns true on success.
bool readGlobalMetadataFile(const string &path, const string &globalKey, string &plaintext) {
    string fileData;
    if (!readFile(path, fileData))
        return false;
    if (fileData.size() < AES_IVLEN)
        return false;
    string iv = fileData.substr(0, AES_IVLEN);
    string ciphertext = fileData.substr(AES_IVLEN);
    try {
        plaintext = aes_decrypt(ciphertext,
                                reinterpret_cast<const unsigned char*>(globalKey.data()),
                                reinterpret_cast<const unsigned char*>(iv.data()));
    } catch (const exception &ex) {
        cerr << "Global metadata decryption failed: " << ex.what() << endl;
        return false;
    }
    return true;
}