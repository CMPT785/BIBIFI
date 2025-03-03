#include "shell.h"
#include "utils.h"
#include "fs_utils.h"
#include "encrypted_fs.h"
#include "crypto_utils.h"
#include "sharing_key_manager.h"
#include "shared_metadata.h"
#include "user_metadata.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <sys/stat.h>
#include <dirent.h>
#include <string>

using namespace std;

// Helper: trim whitespace.
static string trim(const string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if(start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Function to validate input (no '/' or ':')
bool is_valid_input(const string& input) {
    return !input.empty() && 
            input.find('/') == string::npos && 
            input.find('&') == string::npos &&
            input.find("admin") == string::npos &&
            input.find("keyfiles") == string::npos &&
            input.find("metadata") == string::npos &&
            input.find("keyfiles") == string::npos &&
            input.find(':') == string::npos;
}

// Helper: check if str ends with suffix.
static bool endsWith(const string &str, const string &suffix) {
    if (str.length() < suffix.length()) return false;
    return (0 == str.compare(str.length()-suffix.length(), suffix.length(), suffix));
}

// hex encode byte stream
static string serializeEntries(const vector<EnvelopeEntry> &entries) {
    ostringstream oss;
    for (const auto &entry : entries) {
        oss << entry.filePath << " " << toHex(entry.envelope) << "\n";
    }
    return oss.str();
}

// Given a base and a currentRelative (both as strings), compute the actual directory path on disk.
static string computeActualPath(const string &base, const string &currentRelative) {
    if (currentRelative.empty())
        return base;
    else
        return base + "/" + currentRelative;
}

// Check if the current relative directory is forbidden for creation commands.
// For non-admin users, creation in the virtual root ("" representing "/") or in "shared" is forbidden.
static bool isForbiddenCreationDir(const string &normPath, const bool &isAdmin) {
    // admin's allowed modification area is "admin/personal" if base == "filesystem"
    string prefix;
    if (isAdmin) 
        prefix = "admin/personal/";
    else 
        prefix = "personal/";
        
    if (normPath.compare(0, prefix.size(), prefix) == 0) 
        return false;
        
    return true;
}

// Check if the current relative directory is forbidden for share commands.
static bool isForbiddenShareDir(const string &normPath, const bool &isAdmin) {
    string personal_prefix;
    string share_prefix;
    if (isAdmin) {
        personal_prefix = "admin/personal/";
        share_prefix = "admin/shared/";
    } else {
        personal_prefix = "personal/";
        share_prefix = "shared/";
    }
    if (normPath.compare(0, personal_prefix.size(), personal_prefix) == 0 || 
        normPath.compare(0, share_prefix.size(), share_prefix) == 0) 
        return false;
        
    return true;
}

// Command implementations
static void command_cd(const string &base, string &currentRelative, const string &dirArg) {
    string newRel = normalizePath(base, currentRelative, dirArg);
    if (newRel == "XXXFORBIDDENXXX") {
        cout << "Forbidden" << endl;
        return;
    }
    string actual = computeActualPath(base, newRel);
    if (directoryExists(actual)) {
        currentRelative = newRel;
    }
    else
        cout << "Path does Not exist, or is inaccessible." << endl;
}

static void command_pwd(const string &base, const string &currentRelative) {
    if (currentRelative.empty())
        cout << "/" << endl;
    else
        cout << "/" << currentRelative << endl;
}

static void command_ls(const string &base, const string &currentRelative, const string &dirArg) {
    string normPath = normalizePath(base, currentRelative, dirArg);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << "Forbidden" << endl;
        return;
    }
    string dirPath = computeActualPath(base, normPath);
    vector<string> entries;
    if (!listDirectory(dirPath, entries)) {
        cout << "Directory doesn't exist" << endl;
        return;
    }

    for (const auto &name : entries) {

        string fullPath = dirPath + "/" + name;
        struct stat st;
        
        if (name == "." || name == "..")
            cout << "d -> " << name << endl;
        else if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode))
                cout << "d -> " << name << endl;
            else
                cout << "f -> " << name << endl;
        }
    }
}

static void command_cat(const string &base, const string &currentRelative, const string &filename, const string &username, const string &passphrase, const string &userDerivedKey, const string &globalSharingKey) {
    string normPath = normalizePath(base, currentRelative, filename);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << filename << "Forbidden" << endl;
        return;
    }
    string filePath = computeActualPath(base, normPath);
    
    
    // If admin is logged in, check if filePath matches one of our global metadata files.
    if (username == "admin") {
        if (endsWith(filePath, "admin/globalKey.enc")) {
            string plaintext;
            if (!retrieveGlobalSharingKey("admin",
                              "public_keys/admin_keyfile.pem",
                              "filesystem/keyfiles/admin_keyfile.pem",
                              passphrase,
                              plaintext))
                cerr << "Failed to decrypt " << filePath << endl;
            else
                cout << toHex(plaintext) << endl;
            return;
        } 
        if (filePath == "filesystem/metadata/admin/envelopes.enc") {
            vector<EnvelopeEntry> entries;
            loadUserMetadata("admin", userDerivedKey,entries);
            cout << serializeEntries(entries) << endl;
            return;
        }
        if (endsWith(filePath, "share_mappings.mapping") && filePath.find("filesystem/metadata/") == 0) {
            string fileData;
            if (!readFile(filePath, fileData) || fileData.empty())
                return;
            if (fileData.size() < AES_IVLEN) {
                cerr << "Failed to decrypt " << filePath << endl;
                return;
            }
            string iv = fileData.substr(0, AES_IVLEN);
            string ciphertext = fileData.substr(AES_IVLEN);
            string mappingPlaintext;
            try {
                mappingPlaintext = aes_decrypt(ciphertext,
                                            reinterpret_cast<const unsigned char*>(globalSharingKey.data()),
                                            reinterpret_cast<const unsigned char*>(iv.data()));
            } catch (const exception &ex) {
                cerr << "Failed to decrypt " << filePath << endl;
                return;
            }
            cout << mappingPlaintext << endl;
            return;
        }
        if (endsWith(filePath, "shared_envelopes.enc") && filePath.find("filesystem/metadata/") == 0) {
            vector<EnvelopeEntry> entries;
            loadSharedMetadata(username, globalSharingKey,entries);
            cout << serializeEntries(entries) << endl;
            return;
        }
        // For any other file in sensitive directories (like metadata or keyfiles), do not attempt decryption.
        if (filePath.find("filesystem/metadata/") == 0 || filePath.find("filesystem/keyfiles/") == 0) {
            cout << "Forbidden: keys and key data are private, displaying raw encrypted contents:" << endl;
            string raw;
            if (readFile(filePath, raw))
                cout << raw << endl;
            else
                cout << "Unable to read file." << endl;
            return;
        }
    }

    // Otherwise, proceed with normal decryption.
    string decryptedContent;
    bool success = encryptedReadFile(filePath, decryptedContent, username, passphrase, userDerivedKey, globalSharingKey);
    if (success) {
        cout << decryptedContent << endl;
    } else {
        cout << filename << " doesn't exist or decryption failed" << endl;
    }
}

static void command_mkfile(const string &base, const string &currentRelative, const string &filename, 
                           const string &contents, const bool &isAdmin, const string &username, const string &password, 
                           const string &userDerivedKey, const string &globalSharingKey) {
    
    string normPath = normalizePath(base, currentRelative, filename);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << filename << "Forbidden" << endl;
        return;
    }
    
    if (isForbiddenCreationDir(normPath, isAdmin)) {
        cout << "Forbidden" << endl;
        return;
    }
    
    string filePath = computeActualPath(base, normPath);
    if (!encryptedWriteFile(filePath, contents, username, userDerivedKey, globalSharingKey)) {
        cout << "Error creating file" << endl;
    }

}

static void command_mkdir(const string &base, const string &currentRelative, const string &dirname, const bool &isAdmin) {
    
    string normPath = normalizePath(base, currentRelative, dirname);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << "Forbidden" << endl;
        return;
    }

    if (isForbiddenCreationDir(normPath, isAdmin)) {
        cout << "Forbidden" << endl;
        return;
    }
    
    string dirPath = computeActualPath(base, normPath);
    if (directoryExists(dirPath)) {
        cout << "Directory already exists" << endl;
    } else {
        if (!createDirectory(dirPath))
            cout << "Error creating directory" << endl;
    }
}


// Wrap the file's envelope using the global key (which is public)
// and update a central shared envelope mapping (using the old global envelope mapping code).
static void command_share(const string &base, const string &currentRelative,
                          const string &filename, const string &targetUser, 
                          const bool &isAdmin, const string &currentUser, const string &currentUserPass, 
                          const string &senderDerivedKey, const string &globalSharingKey) {

    string normPath = normalizePath(base, currentRelative, filename);
    if (normPath == "XXXFORBIDDENXXX" || isForbiddenShareDir(normPath, isAdmin)) {
        cout << "Forbidden" << endl;
        return;
    }
    string sourceFile = computeActualPath(base, normPath);
    if (!fileExists(sourceFile)) {
        cout << "File " << filename << " doesn't exist" << endl;
        return;
    }
    // Read file envelope for currentUser.
    string currentEnvelope;
    if (!findUserEnvelope(currentUser, sourceFile, senderDerivedKey, currentEnvelope)) {
        cout << "Error: envelope mapping missing for current file" << endl;
        return;
    }
    
    // Decrypt it using current user's private key.
    string currentPrivKeyPath = "filesystem/keyfiles/" + currentUser + "_keyfile.pem";
    
    RSA* rsaPriv = load_private_key(currentPrivKeyPath, currentUserPass);
    if (!rsaPriv) {
        cout << "Error: could not load your private key (perhaps incorrect passphrase)." << endl;
        return;
    }
    string keyIV;
    try {
        keyIV = rsa_decrypt(rsaPriv, currentEnvelope);
    } catch (const exception &ex) {
        cout << "Error decrypting envelope: " << ex.what() << endl;
        RSA_free(rsaPriv);
        return;
    }
    RSA_free(rsaPriv);

    // clean copy
    string clearIV = keyIV;
    
    // we wrap keyIV symmetrically using the global sharing key. 
    // This means that the target user will later use their copy of the
    // global sharing key to unwrap the envelope.
    unsigned char symIV[AES_IVLEN];
    if (RAND_bytes(symIV, AES_IVLEN) != 1) {
        cout << "Failed to generate IV for sharing encryption." << endl;
        return;
    }
    string symIVStr(reinterpret_cast<char*>(symIV), AES_IVLEN);
    string wrappedEnvelope;
    try {
        wrappedEnvelope = aes_encrypt(keyIV, reinterpret_cast<const unsigned char*>(globalSharingKey.data()), symIV);
    } catch (const exception &ex) {
        cout << "Error encrypting file key with global sharing key: " << ex.what() << endl;
        return;
    }
    // Prepend the IV to the ciphertext so that it can be used for decryption later.
    string newEnvelope = symIVStr + wrappedEnvelope;

    // Additionally, create a hard link in the target user's shared directory.
    // Target user's shared directory: "filesystem/<targetUser>/shared"
    // Determine the relative path portion based on whether the source file is under "personal" or "shared".
    string relativePath;
    string personalPrefix;
    string sharedPrefix;
    if (isAdmin) {
        personalPrefix = "admin/personal/";
        sharedPrefix = "admin/shared/";
    } else {
        personalPrefix = "personal/";
        sharedPrefix = "shared/";
    }
    if (normPath.compare(0, personalPrefix.size(), personalPrefix) == 0) {
        // File is in personal directory.
        relativePath = normPath.substr(personalPrefix.size());
    } else if (normPath.compare(0, sharedPrefix.size(), sharedPrefix) == 0) {
        // File is already in a shared directory.
        relativePath = normPath.substr(sharedPrefix.size());
    } else {
        // File is not under a recognized subfolder; use entire normalized path.
        relativePath = "";
        cerr << "Warning: could not replicate directory structure, file will be available at: " << targetUser + "/shared/"  << endl;
    }
    
    // Build target normalized path: "shared/<relativePath>"
    string targetNormPath = normalizePath("filesystem/" + targetUser, "", "shared/" + currentUser + "/" + relativePath);
    // Compute the actual target file path.
    string targetFile = computeActualPath("filesystem/" + targetUser, targetNormPath);
    
    // Ensure target directory exists.
    size_t lastSlash = targetFile.find_last_of('/');
    if (lastSlash != string::npos) {
        string targetDir = targetFile.substr(0, lastSlash);
        if (!directoryExists(targetDir)) {
            if (!createDirectories(targetDir)) {
                cout << "Failed to create target directory structure: " << targetDir << endl;
                return;
            }
        }
    }

    // Update the target's shared metadata.
    // This encrypts the shared envelope under the global sharing key.
    if (updateSharedEnvelopeEntry(targetUser, globalSharingKey, targetFile, newEnvelope))
        cout << "File shared with " << targetUser << endl;
    else {
        cout << "Failed to update shared envelope mapping for " << targetUser << endl;
        return;
    }

    // Now update admin access
    // Call the function to re-wrap the clear keyIV for admin using the global sharing key.
    if (targetUser != "admin") {
        if (!updateAdminAccessForFile(targetUser, senderDerivedKey, globalSharingKey, targetFile, clearIV)) {
            cerr << "Warning: failed to update admin access for file: " << targetFile << endl;
            return;
        }
    }

    // Update share mapping
    const string mappingFilePath = "filesystem/metadata/share_mappings.mapping";
    if (!updateShareMapping(mappingFilePath, sourceFile, targetUser, targetFile, globalSharingKey)) {
        cout << "Failed to update share mappings." << endl;
        return;
    }
    
    // Create a hard link at the target location.
    if (fileExists(targetFile))
        removeFile(targetFile);
    if (!createHardLink(sourceFile, targetFile))
        cout << "Error sharing file at " << targetFile << endl;
}


// This function generates an RSA key pair for the new user,
// stores the public key outside the filesystem (as "<username>_keyfile.pem"),
// stores the private key (encrypted with a randomly generated passphrase) in "filesystem/keyfiles/<username>_keyfile.pem",
// and creates the user's directory structure.
void command_adduser(const string &username, const string &globalKey) {

    string newUser = trim(username);

    if (!is_valid_input(newUser)) {
        cerr << "Invalid username. Please try again." << endl;
        return;
    }

    string userDir = "filesystem/" + newUser;
    if (directoryExists(userDir)) {
        cout << "User " << newUser << " already exists" << endl;
        return;
    }
    
    // Generate a temporary passphrase for the new user.
    string tempPassphrase = generateRandomPassphrase();
    
    // Paths for key files.
    string privateKeyPath = "filesystem/keyfiles/" + newUser + "_keyfile.pem";
    string publicKeyPath  = "public_keys/" + newUser + "_keyfile.pem";
    
    // Generate the RSA key pair, encrypting the private key with the temporary passphrase.
    if (!generate_rsa_keypair(privateKeyPath, publicKeyPath, tempPassphrase)) {
        cout << "Error creating keyfiles for " << newUser << endl;
        return;
    }
    
    // Create the user's filesystem directory and subdirectories.
    if (!createDirectory(userDir)) {
        cout << "Error creating user directory for " << newUser << endl;
        return;
    }
    createDirectory(userDir + "/personal");
    createDirectory(userDir + "/shared");
    
    // Create the user's metadata directory.
    string metaDir = "filesystem/metadata/" + newUser;
    if (!directoryExists(metaDir)) {
        if (!createDirectory(metaDir)) {
            cout << "Error creating metadata directory for " << newUser << endl;
            return;
        }
    }
    
    // Grant the new user access to the global sharing key.
    if (!grantUserAccessToGlobalKey(newUser, publicKeyPath)) {
        cout << "Error granting access to global sharing key." << endl;
        return;
    }
    
    // Inform the admin that the new user was created and display the temporary passphrase.
    cout << "Added user: " << newUser << endl;
    cout << "Temporary passphrase for " << newUser << " is: " << tempPassphrase << endl;
    cout << "User must change this passphrase at first login." << endl;
}

void command_changepass(const string &currentUser, const string &oldPass, const string &newPass) {
    // Re-encrypt the private key.
    string privKeyPath = "filesystem/keyfiles/" + currentUser + "_keyfile.pem";
    RSA* rsa = load_private_key(privKeyPath, oldPass);
    if (!rsa) {
        cout << "Failed to load your current private key. Incorrect old passphrase?" << endl;
        return;
    }
    FILE* fp = fopen(privKeyPath.c_str(), "w");
    if (!fp) {
        cout << "Failed to open your private key file for writing." << endl;
        RSA_free(rsa);
        return;
    }
    if (!PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), nullptr, 0, nullptr, const_cast<char*>(newPass.c_str()))) {
        cout << "Failed to re-encrypt your private key." << endl;
        fclose(fp);
        RSA_free(rsa);
        return;
    }
    fclose(fp);
    RSA_free(rsa);
    
    // Now re-encrypt the metadata file.
    // Derive old and new keys.
    string oldDerivedKey = deriveKeyFromPassword(oldPass);
    string newDerivedKey = deriveKeyFromPassword(newPass);
    // Load current metadata.
    vector<EnvelopeEntry> entries;
    if (!loadUserMetadata(currentUser, oldDerivedKey, entries)) {
        cout << "Failed to load your metadata for password change." << endl;
        return;
    }
    // Save metadata with new derived key.
    if (!saveUserMetadata(currentUser, newDerivedKey, entries)) {
        cout << "Failed to update your metadata encryption." << endl;
        return;
    }
    cout << "Password changed successfully." << endl;
    cout << "Please Log in Again to re-initialize." << endl;
}


void shellLoop(const string &base, bool isAdmin, 
               const string &currentUser, const string &userPass, 
               const string &globalSharingKey, const string &userDerivedKey) {
    // currentRelative represents the virtual location relative to the user’s root.
    // For virtual root, we use an empty string ("").

    string currentRelative = "";
    string line;
    while (true) {
        cout << currentRelative << "> ";
        if (!getline(cin, line))
            break;
        line = trim(line);
        if (line.empty())
            continue;
        istringstream iss(line);
        string command;
        iss >> command;
        if (command == "exit") {
            break;
        } else if (command == "cd") {
            string dirArg;
            if (!(iss >> dirArg)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_cd(base, currentRelative, dirArg);
        } else if (command == "pwd") {
            command_pwd(base, currentRelative);
        } else if (command == "ls") {
            string dirArg;
            if (!(iss >> dirArg)) {
                command_ls(base, currentRelative, "");
            } else 
                command_ls(base, currentRelative, dirArg);
        } else if (command == "cat") {
            string filename;
            if (!(iss >> filename)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_cat(base, currentRelative, filename, currentUser, userPass, userDerivedKey, globalSharingKey);
        } else if (command == "mkfile") {
            string filename;
            if (!(iss >> filename)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            string contents;
            getline(iss, contents);
            contents = trim(contents);
            command_mkfile(base, currentRelative, filename, contents, 
                           isAdmin, currentUser, userPass, 
                           userDerivedKey, globalSharingKey);
        } else if (command == "mkdir") {
            string dirname;
            if (!(iss >> dirname) || !is_valid_input(dirname)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_mkdir(base, currentRelative, dirname, isAdmin);
        } else if (command == "share") {
            string filename, targetUser;
            if (!(iss >> filename >> targetUser)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_share(base, currentRelative, filename, targetUser, isAdmin, currentUser, userPass, userDerivedKey, globalSharingKey);
        } else if (command == "changepass") {
            cout << "Enter current passphrase: ";
            string oldPass;
            getline(cin, oldPass);
            oldPass = trim(oldPass);
            cout << "Enter new passphrase: ";
            string newPass;
            getline(cin, newPass);
            newPass = trim(newPass);
            cout << "Confirm new passphrase: ";
            string confirmPass;
            getline(cin, confirmPass);
            confirmPass = trim(confirmPass);
            if (newPass != confirmPass || newPass.empty()) {
                cout << "Passphrases do not match or are empty." << endl;
                continue;
            }
            command_changepass(currentUser, oldPass, newPass); 
            break;
        } else if (command == "adduser") {
            if (!isAdmin) {
                cout << "Invalid Command" << endl;
                continue;
            }
            string newUser;
            if (!(iss >> newUser)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_adduser(newUser, globalSharingKey);
        } else {
            cout << "Invalid Command" << endl;
        }
    }
}
