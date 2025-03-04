#ifndef SHARED_METADATA_H
#define SHARED_METADATA_H

#include <string>
#include <vector>
#include "user_metadata.h"

using namespace std;

// Shared metadata functions (for files shared with a user)
bool loadSharedMetadata(const string &username, const string &globalKey, vector<EnvelopeEntry> &entries);
bool saveSharedMetadata(const string &username, const string &globalKey, const vector<EnvelopeEntry> &entries);
bool updateSharedEnvelopeEntry(const string &username, const string &globalKey, const string &filePath, const string &envelope);
bool findUserSharedEnvelope(const string &username, const string &filePath, const string &globalKey, string &envelope);

// Share mapping functions
bool updateShareMapping(const string &mappingFilePath, const string &filePath, const string &targetUser, const string &targetFile, const string &sharingKey);
vector<string> getSharedRecipientsForFile(const string &mappingFilePath, const string &filePath, const string &sharingKey);
bool updateRecursiveShare(const string &owner, const string &ownerDerivedKey, const string &filePath, const string &globalSharingKey, const string &clearKeyIV);


#endif // SHARED_METADATA_H
