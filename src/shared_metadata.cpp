#include "utils.h"
#include "shared_metadata.h"
#include "fs_utils.h"
#include "crypto_utils.h"

#include <openssl/rand.h>

#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <string>

using namespace std;

// For simplicity, we assume AES_IVLEN is defined in crypto_utils.h
extern const int AES_IVLEN;

static string serializeEntries(const vector<EnvelopeEntry> &entries) {
    ostringstream oss;
    for (const auto &entry : entries) {
        oss << entry.filePath << " " << toHex(entry.envelope) << "\n";
    }
    return oss.str();
}

static bool deserializeEntries(const string &data, vector<EnvelopeEntry> &entries) {
    istringstream iss(data);
    string line;
    while (getline(iss, line)) {
        if (line.empty()) continue;
        istringstream linestream(line);
        EnvelopeEntry entry;
        if (!(linestream >> entry.filePath >> entry.envelope))
            return false;

        entry.envelope = fromHex(entry.envelope);
        entries.push_back(entry);
    }
    return true;
}

bool loadSharedMetadata(const string &username,
                        const string &globalKey,
                        vector<EnvelopeEntry> &entries) {
    string metaPath = "filesystem/metadata/" + username + "/shared_envelopes.enc";
    string fileData;
    if (!readFile(metaPath, fileData) || fileData.size() < AES_IVLEN) {
        // If the file does not exist or is too small, initialize it with a default entry.
        vector<EnvelopeEntry> defaultEntries;
        EnvelopeEntry defaultEntry;
        defaultEntry.filePath = "filesystem/metadata/" + username + "/create.init";
        defaultEntry.envelope = "entry1"; // Placeholder value.
        if (!saveSharedMetadata(username, globalKey, defaultEntries)) {
            cerr << "Error initializing shared metadata for " << username << endl;
            return false;
        }
        if (!readFile(metaPath, fileData)) {
            cerr << "Failed to read shared metadata after initialization for " << username << endl;
            return false;
        }
    }
    if (fileData.size() < AES_IVLEN) {
        cerr << "Shared metadata file corrupt (too small)." << endl;
        return false;
    }
    
    string iv = fileData.substr(0, AES_IVLEN);
    string ciphertext = fileData.substr(AES_IVLEN);
    string plaintext;
    try {
        plaintext = aes_decrypt(ciphertext,
                                reinterpret_cast<const unsigned char*>(globalKey.data()),
                                reinterpret_cast<const unsigned char*>(iv.data()));
    } catch (const exception &ex) {
        cerr << "Failed to decrypt shared metadata: " << ex.what() << endl;
        return false;
    }
    return deserializeEntries(plaintext, entries);
}

bool saveSharedMetadata(const string &username,
                        const string &globalKey,
                        const vector<EnvelopeEntry> &entries) {
    string metaPath = "filesystem/metadata/" + username + "/shared_envelopes.enc";
    string plaintext = serializeEntries(entries);
    unsigned char iv[AES_IVLEN];
    if (RAND_bytes(iv, AES_IVLEN) != 1) {
        cerr << "Failed to generate IV for shared metadata" << endl;
        return false;
    }
    string ivStr(reinterpret_cast<char*>(iv), AES_IVLEN);
    string ciphertext;
    try {
        ciphertext = aes_encrypt(plaintext,
                                 reinterpret_cast<const unsigned char*>(globalKey.data()),
                                 iv);
    } catch (const exception &ex) {
        cerr << "Encryption of shared metadata failed: " << ex.what() << endl;
        return false;
    }
    return writeFile(metaPath, ivStr + ciphertext);
}

bool updateSharedEnvelopeEntry(const string &username,
                               const string &globalKey,
                               const string &filePath,
                               const string &envelope) {
    vector<EnvelopeEntry> entries;
    loadSharedMetadata(username, globalKey, entries);
    bool found = false;
    for (auto &entry : entries) {
        if (entry.filePath == filePath) {
            entry.envelope = envelope; // envelope should be hex encoded already
            found = true;
            break;
        }
    }
    if (!found) {
        EnvelopeEntry newEntry;
        newEntry.filePath = filePath;
        newEntry.envelope = envelope;
        entries.push_back(newEntry);
    }
    return saveSharedMetadata(username, globalKey, entries);
}


bool findUserSharedEnvelope(const string &username,
                      const string &filePath,
                      const string &globalKey,
                      string &envelope) {
    vector<EnvelopeEntry> entries;
    // Load the user's metadata from the encrypted file.
    if (!loadSharedMetadata(username, globalKey, entries)) {
        cerr << "Failed to load metadata for user " << username << endl;
        return false;
    }
    // Iterate over all entries and return the envelope for the matching filePath.
    for (const auto &entry : entries) {
        if (entry.filePath == filePath) {
            envelope = entry.envelope;
            return true;
        }
    }
    // If no matching entry is found, return false.
    return false;
}


// Updates (or creates) a mapping line for a file so that targetUser is added as a recipient.
// The file is encrypted with the global key.
bool updateShareMapping(const string &mappingFilePath,
                        const string &sourceFile,        // source file path
                        const string &targetUser,
                        const string &targetFile,        // the target file path
                        const string &sharingKey) {
    // Read existing mapping file.
    string fileData;
    if (!readFile(mappingFilePath, fileData))
        fileData = "";
    
    // Decrypt the mapping file if it exists.
    string plaintext;
    if (!fileData.empty()) {
        if (fileData.size() < AES_IVLEN) {
            cerr << "Share mappings file corrupt: too small." << endl;
            return false;
        }
        string iv = fileData.substr(0, AES_IVLEN);
        string ciphertext = fileData.substr(AES_IVLEN);
        try {
            plaintext = aes_decrypt(ciphertext,
                                    reinterpret_cast<const unsigned char*>(sharingKey.data()),
                                    reinterpret_cast<const unsigned char*>(iv.data()));
        } catch (const exception &ex) {
            cerr << "Failed to decrypt share mappings file: " << ex.what() << endl;
            return false;
        }
    }
    
    // The mapping is line-based.
    // Each line: <source_file> recipient1:targetFile1 recipient2:targetFile2 ...
    istringstream iss(plaintext);
    vector<string> lines;
    string line;
    bool foundLine = false;
    for (; getline(iss, line); ) {
        if (!line.empty())
            lines.push_back(line);
    }
    
    // Try to find an existing mapping for the source file.
    bool updated = false;
    for (size_t i = 0; i < lines.size(); i++) {
        istringstream lineStream(lines[i]);
        string token;
        vector<string> tokens;
        while (lineStream >> token) {
            tokens.push_back(token);
        }
        if (!tokens.empty() && tokens[0] == sourceFile) {
            // Look for targetUser token.
            bool alreadyPresent = false;
            for (size_t j = 1; j < tokens.size(); j++) {
                // Expect token of form "user:targetPath"
                size_t pos = tokens[j].find(":");
                if (pos != string::npos) {
                    string user = tokens[j].substr(0, pos);
                    if (user == targetUser) {
                        // Update target path in case it has changed.
                        tokens[j] = targetUser + ":" + targetFile;
                        alreadyPresent = true;
                        updated = true;
                        break;
                    }
                }
            }
            if (!alreadyPresent) {
                tokens.push_back(targetUser + ":" + targetFile);
                updated = true;
            }
            // Reassemble the line.
            ostringstream oss;
            for (size_t j = 0; j < tokens.size(); j++) {
                oss << tokens[j];
                if (j < tokens.size() - 1)
                    oss << " ";
            }
            lines[i] = oss.str();
            foundLine = true;
            break;
        }
    }
    
    // If no mapping exists for the source file, add a new line.
    if (!foundLine) {
        ostringstream oss;
        oss << sourceFile << " " << targetUser << ":" << targetFile;
        lines.push_back(oss.str());
        updated = true;
    }
    
    // Reassemble all lines.
    ostringstream finalOss;
    for (const auto &l : lines)
        finalOss << l << "\n";
    string newPlaintext = finalOss.str();
    
    // Encrypt newPlaintext with the sharing key.
    unsigned char newIv[AES_IVLEN];
    if (RAND_bytes(newIv, AES_IVLEN) != 1) {
        cerr << "Failed to generate IV for share mappings." << endl;
        return false;
    }
    string newIvStr(reinterpret_cast<char*>(newIv), AES_IVLEN);
    string newCiphertext;
    try {
        newCiphertext = aes_encrypt(newPlaintext,
                                    reinterpret_cast<const unsigned char*>(sharingKey.data()),
                                    newIv);
    } catch (const exception &ex) {
        cerr << "Encryption of share mappings failed: " << ex.what() << endl;
        return false;
    }
    string finalData = newIvStr + newCiphertext;
    return writeFile(mappingFilePath, finalData);
}


// get the users shread to for the file
vector<string> getSharedRecipientsForFile(const string &mappingFilePath,
                                                     const string &filePath,
                                                     const string &sharingKey) {
    vector<string> recipients;
    string fileData;
    if (!readFile(mappingFilePath, fileData)) {
        return recipients;
    }
    if (fileData.size() < AES_IVLEN) {
        cerr << "Share mappings file corrupt: too small." << endl;
        return recipients;
    }
    string iv = fileData.substr(0, AES_IVLEN);
    string ciphertext = fileData.substr(AES_IVLEN);
    string plaintext;
    try {
        plaintext = aes_decrypt(ciphertext,
                                reinterpret_cast<const unsigned char*>(sharingKey.data()),
                                reinterpret_cast<const unsigned char*>(iv.data()));
    } catch (const exception &ex) {
        cerr << "Failed to decrypt share mappings file: " << ex.what() << endl;
        return recipients;
    }
    istringstream iss(plaintext);
    string line;
    while (getline(iss, line)) {
        if (line.empty())
            continue;
        istringstream lineStream(line);
        vector<string> tokens;
        string token;
        while (lineStream >> token) {
            tokens.push_back(token);
        }
        if (!tokens.empty() && tokens[0] == filePath) {
            // All tokens after the first are recipients.
            for (size_t i = 1; i < tokens.size(); i++) {
                recipients.push_back(tokens[i]);
            }
            break;
        }
    }
    return recipients;
}

// This function performs a recursive update of shared envelopes for a given file.
// It looks up all recipients for the file from the share mappings file (encrypted with the global sharing key)
// and then re–wraps the owner’s current envelope using the global sharing key and updates each recipient's shared metadata.
bool updateRecursiveShare(const string &owner,
                          const string &ownerDerivedKey,
                          const string &filePath,
                          const string &globalSharingKey, 
                          const string &clearKeyIV) {
    
    // Check that clearKeyIV is valid.
    if (clearKeyIV.size() != AES_KEYLEN + AES_IVLEN) {
        cerr << "Provided clearKeyIV has invalid length: " << clearKeyIV.size() << endl;
        return false;
    }
    
    // Read share mappings.
    const string shareMappingFile = "filesystem/metadata/share_mappings.mapping";
    string fileData;
    if (!readFile(shareMappingFile, fileData) || fileData.empty()) {
        // No mapping exists: nothing to update.
        return true;
    }
    if (fileData.size() < AES_IVLEN) {
        cerr << "Share mappings file corrupt: too small." << endl;
        return false;
    }
    string iv = fileData.substr(0, AES_IVLEN);
    string ciphertext = fileData.substr(AES_IVLEN);
    string mappingPlaintext;
    try {
        mappingPlaintext = aes_decrypt(ciphertext,
                                       reinterpret_cast<const unsigned char*>(globalSharingKey.data()),
                                       reinterpret_cast<const unsigned char*>(iv.data()));
    } catch (const exception &ex) {
        cerr << "Failed to decrypt share mappings file: " << ex.what() << endl;
        return false;
    }
    
    // Find the mapping line corresponding to source file.
    istringstream iss(mappingPlaintext);
    vector<string> lines;
    string line;
    bool foundMappingLine = false;
    string mappingLine;
    while (getline(iss, line)) {
        if (line.empty())
            continue;
        istringstream lineStream(line);
        string key;
        lineStream >> key;
        if (key == filePath) {
            mappingLine = line;
            foundMappingLine = true;
            break;
        }
    }
    if (!foundMappingLine) {
        // Nothing to update.
        return true;
    }
    
    // Parse the mapping line: each token after the first is of the form "recipient:targetFile".
    istringstream lineStream(mappingLine);
    string dummy;
    lineStream >> dummy;  // consume filePath token
    vector<pair<string,string>> mappings;
    string token;
    while (lineStream >> token) {
        size_t pos = token.find(":");
        if (pos != string::npos) {
            string recipient = token.substr(0, pos);
            string targetFile = token.substr(pos+1);
            mappings.push_back(make_pair(recipient, targetFile));
        }
    }
    
    // For each mapping, re-wrap the clear keyIV using the global sharing key.
    for (const auto &mapping : mappings) {
        const string &recipient = mapping.first;
        const string &targetFile = mapping.second;
        unsigned char symIV[AES_IVLEN];
        if (RAND_bytes(symIV, AES_IVLEN) != 1) {
            cerr << "Failed to generate IV for sharing encryption for recipient: " << recipient << endl;
            continue;
        }
        string symIVStr(reinterpret_cast<char*>(symIV), AES_IVLEN);
        string newWrappedEnvelope;
        try {
            newWrappedEnvelope = aes_encrypt(clearKeyIV,
                                             reinterpret_cast<const unsigned char*>(globalSharingKey.data()),
                                             symIV);
        } catch (const exception &ex) {
            cerr << "Error encrypting envelope for recipient " << recipient << ": " << ex.what() << endl;
            continue;
        }
        string finalEnvelope = symIVStr + newWrappedEnvelope;
        // Update the recipient's shared metadata using the target file path from the mapping.
        if (!updateSharedEnvelopeEntry(recipient, globalSharingKey, targetFile, finalEnvelope)) {
            cerr << "Failed to update shared envelope for recipient: " << recipient << endl;
        }/* else {
            cout << "Updated shared envelope for " << recipient << endl;
        }*/
    }
    
    return true;
}
