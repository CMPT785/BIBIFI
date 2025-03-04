#include "utils.h"
#include "user_metadata.h"
#include "fs_utils.h"
#include "crypto_utils.h"

#include <openssl/rand.h>

#include <sstream>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <iomanip>
#include <string>

using namespace std;


// For simplicity, we use the AES_IVLEN defined in crypto_utils.h.
extern const int AES_IVLEN; // assume this is defined (e.g., 16)

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

bool loadUserMetadata(const string &username,
                      const string &derivedKey,
                      vector<EnvelopeEntry> &entries) {
    string metaPath = "filesystem/metadata/" + username + "/envelopes.enc";
    string fileData;
    if (!readFile(metaPath, fileData) || fileData.size() < AES_IVLEN) {
        // Metadata file is missing or too small, so initialize it with a default entry.
        vector<EnvelopeEntry> defaultEntries;
        EnvelopeEntry defaultEntry;
        defaultEntry.filePath = "create.init";
        defaultEntry.envelope = "entry1"; // This is a placeholder; it's not used for decryption.
        if (!saveUserMetadata(username, derivedKey, defaultEntries)) {
            cerr << "Error initializing user metadata for " << username << endl;
            return false;
        }
        if (!readFile(metaPath, fileData)) {
            cerr << "Failed to read metadata after initialization for " << username << endl;
            return false;
        }
    }
    if (fileData.size() < AES_IVLEN) {
        cerr << "User metadata file corrupt (too small)." << endl;
        return false;
    }
    string iv = fileData.substr(0, AES_IVLEN);
    string ciphertext = fileData.substr(AES_IVLEN);
    string plaintext;
    try {
        plaintext = aes_decrypt(ciphertext,
                                reinterpret_cast<const unsigned char*>(derivedKey.data()),
                                reinterpret_cast<const unsigned char*>(iv.data()));
    } catch (const exception &ex) {
        cerr << "Failed to decrypt user metadata: " << ex.what() << endl;
        return false;
    }
    return deserializeEntries(plaintext, entries);
}

// Helper: Find the envelope entry for a file from a user's personal metadata.
// Returns true and sets 'envelope' if found.
bool findUserEnvelope(const string &username, const string &filePath, 
                      const string &derivedKey, string &envelope) {
    vector<EnvelopeEntry> entries;
    if (!loadUserMetadata(username, derivedKey, entries)) {
        cerr << "Failed to load user metadata for " << username << endl;
        return false;
    }

    for (const auto &entry : entries) {
        if (entry.filePath == filePath) {
            envelope = entry.envelope;
            return true;
        }
    }
    return false;
}

bool saveUserMetadata(const string &username,
                      const string &derivedKey,
                      const vector<EnvelopeEntry> &entries) {
    string metaPath = "filesystem/metadata/" + username + "/envelopes.enc";
    string plaintext = serializeEntries(entries);
    unsigned char iv[AES_IVLEN];
    if (RAND_bytes(iv, AES_IVLEN) != 1) {
        cerr << "Failed to generate IV for user metadata" << endl;
        return false;
    }
    string ivStr(reinterpret_cast<char*>(iv), AES_IVLEN);
    string ciphertext;
    try {
        ciphertext = aes_encrypt(plaintext,
                                 reinterpret_cast<const unsigned char*>(derivedKey.data()),
                                 iv);
    } catch (const exception &ex) {
        cerr << "Encryption of user metadata failed: " << ex.what() << endl;
        return false;
    }
    return writeFile(metaPath, ivStr + ciphertext);
}

bool updateUserEnvelopeEntry(const string &username,
                             const string &derivedKey,
                             const string &filePath,
                             const string &envelope) {
    vector<EnvelopeEntry> entries;
    loadUserMetadata(username, derivedKey, entries);
    bool found = false;
    for (auto &entry : entries) {
        if (entry.filePath == filePath) {
            entry.envelope = envelope; // assume envelope is already hex encoded
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
    
    return saveUserMetadata(username, derivedKey, entries);
}
