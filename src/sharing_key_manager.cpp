#include "sharing_key_manager.h"
#include "crypto_utils.h"
#include "fs_utils.h"
#include "encrypted_fs.h"
#include "user_metadata.h"
#include "shared_metadata.h"

#include <openssl/rand.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <string>


using namespace std;

// We'll store the global sharing key in memory here.
static string gGlobalSharingKey = "";

// File where the global sharing key (wrapped by admin) is stored.
static const string kGlobalKeyFile = "filesystem/metadata/admin/globalKey.enc";

// Initializes the global sharing key.
bool initGlobalSharingKey(const string &adminPublicKeyPath,
                          const string &adminPrivateKeyPath,
                          const string &adminPassphrase, 
                          string &globalKey) {
    string encryptedKey;
    if (!fileExists(kGlobalKeyFile)) {
        // First time: generate a new 32-byte key.
        unsigned char buf[32];
        if (RAND_bytes(buf, sizeof(buf)) != 1) {
            cerr << "Failed to generate global sharing key" << endl;
            return false;
        }
        gGlobalSharingKey = string(reinterpret_cast<char*>(buf), 32);
        // Encrypt it with admin's public key.
        RSA *rsaPub = load_public_key(adminPublicKeyPath);
        if (!rsaPub) {
            cerr << "Failed to load admin public key from " << adminPublicKeyPath << endl;
            return false;
        }
        try {
            encryptedKey = rsa_encrypt(rsaPub, gGlobalSharingKey);
        } catch (const exception &ex) {
            cerr << "Error encrypting global sharing key: " << ex.what() << endl;
            RSA_free(rsaPub);
            return false;
        }
        RSA_free(rsaPub);
        // Save the wrapped key to disk.
        if (!writeFile(kGlobalKeyFile, encryptedKey)) {
            cerr << "Failed to write global sharing key file" << endl;
            return false;
        }
    } else {
        // Read and decrypt the global key using admin's private key.
        if (!readFile(kGlobalKeyFile, encryptedKey)) {
            cerr << "Failed to read global sharing key file" << endl;
            return false;
        }
        RSA *rsaPriv = load_private_key(adminPrivateKeyPath, adminPassphrase);
        if (!rsaPriv) {
            cerr << "Failed to load admin private key from " << adminPrivateKeyPath << endl;
            return false;
        }
        try {
            gGlobalSharingKey = rsa_decrypt(rsaPriv, encryptedKey);
        } catch (const exception &ex) {
            cerr << "Error decrypting global sharing key: " << ex.what() << endl;
            RSA_free(rsaPriv);
            return false;
        }
        RSA_free(rsaPriv);
    }
    return true;
}

// Grants a user access to the global sharing key.
bool grantUserAccessToGlobalKey(const string &username,
                                const string &userPublicKeyPath) {
    if (gGlobalSharingKey.empty()) {
        cerr << "Global sharing key is not initialized." << endl;
        return false;
    }
    RSA *rsaUser = load_public_key(userPublicKeyPath);
    if (!rsaUser) {
        cerr << "Failed to load user public key from " << userPublicKeyPath << endl;
        return false;
    }
    string wrappedKey;
    try {
        wrappedKey = rsa_encrypt(rsaUser, gGlobalSharingKey);
    } catch (const exception &ex) {
        cerr << "Error wrapping global sharing key for user: " << ex.what() << endl;
        RSA_free(rsaUser);
        return false;
    }
    RSA_free(rsaUser);
    // Save wrapped key into user's metadata directory.
    string userMetaDir = "filesystem/metadata/" + username;
    if (!directoryExists(userMetaDir))
        createDirectory(userMetaDir);
    string targetFile = userMetaDir + "/globalKey.enc";
    return writeFile(targetFile, wrappedKey);
}

// Retrieves the global sharing key for a user.
// The user provides their private key (unlocked with their pass) to unwrap it.
bool retrieveGlobalSharingKey(const string &username,
                              const string &userPublicKeyPath,
                              const string &userPrivateKeyPath,
                              const string &userPass,
                              string &globalKey) {
    string wrappedKey;
    string userMetaDir = "filesystem/metadata/" + username;
    string targetFile = userMetaDir + "/globalKey.enc";
    if (!readFile(targetFile, wrappedKey)) {
        cerr << "Failed to read wrapped global key" << endl;
        return false;
    }
    RSA *rsa = load_private_key(userPrivateKeyPath, userPass);
    if (!rsa) {
        cerr << "Failed to load user's private key" << endl;
        return false;
    }
    try {
        globalKey = rsa_decrypt(rsa, wrappedKey);
    } catch (const exception &ex) {
        cerr << "Error unwrapping global sharing key: " << ex.what() << endl;
        RSA_free(rsa);
        return false;
    }
    RSA_free(rsa);
    return true;
}

// Every file should be read only to admin
bool updateAdminAccessForFile(const string &owner,
                              const string &ownerDerivedKey,
                              const string &globalSharingKey,
                              const string &filePath,
                              const string &clearKeyIV) {
    // clearKeyIV should be the concatenation of the AES key (AES_KEYLEN bytes)
    // and the AES IV (AES_IVLEN bytes) used to encrypt the file.
    if (clearKeyIV.size() != AES_KEYLEN + AES_IVLEN) {
        cerr << "Invalid clearKeyIV length." << endl;
        return false;
    }
    
    // Generate a fresh IV for wrapping with the global sharing key.
    unsigned char symIV[AES_IVLEN];
    if (RAND_bytes(symIV, AES_IVLEN) != 1) {
        cerr << "Failed to generate IV for admin wrapping." << endl;
        return false;
    }
    string symIVStr(reinterpret_cast<char*>(symIV), AES_IVLEN);
    
    string adminWrappedEnvelope;
    try {
        // Encrypt clearKeyIV using AES with the global sharing key.
        adminWrappedEnvelope = aes_encrypt(clearKeyIV,
                                           reinterpret_cast<const unsigned char*>(globalSharingKey.data()),
                                           symIV);
    } catch (const exception &ex) {
        cerr << "Error encrypting admin envelope: " << ex.what() << endl;
        return false;
    }
    // Prepend the IV to the ciphertext.
    string finalAdminEnvelope = symIVStr + adminWrappedEnvelope;

    // Update the admin's shared metadata for this file.
    if (!updateSharedEnvelopeEntry("admin", globalSharingKey, filePath, finalAdminEnvelope)) {
        cerr << "Failed to update admin's shared envelope for file " << filePath << endl;
        return false;
    }

    // Update share mapping
    const string mappingFilePath = "filesystem/metadata/share_mappings.mapping";
    if (!updateShareMapping(mappingFilePath, filePath, "admin", filePath, globalSharingKey)) {
        cout << "Failed to update share mappings." << endl;
        return false;
    }

    return true;
}

