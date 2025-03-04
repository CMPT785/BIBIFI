#ifndef USER_METADATA_H
#define USER_METADATA_H

#include <string>
#include <vector>

using namespace std;

// EnvelopeEntry stores the file path and its wrapped AES key/IV (envelope)
struct EnvelopeEntry {
    string filePath;
    string envelope;
};

// User metadata functions
bool findUserEnvelope(const string &username, const string &filePath, 
                      const string &derivedKey, string &envelope);
bool loadUserMetadata(const string &username, const string &derivedKey, vector<EnvelopeEntry> &entries);
bool saveUserMetadata(const string &username, const string &derivedKey, const vector<EnvelopeEntry> &entries);
bool updateUserEnvelopeEntry(const string &username, const string &derivedKey, const string &filePath, const string &envelope);

#endif // USER_METADATA_H
