#ifndef SHARING_KEY_MANAGER_H
#define SHARING_KEY_MANAGER_H

#include <string>

using namespace std;

// Global sharing key management functions
bool initGlobalSharingKey(const string &adminPublicKeyPath,
                          const string &adminPrivateKeyPath,
                          const string &adminPassphrase, 
                          string &globalKey);
bool grantUserAccessToGlobalKey(const string &username, const string &userPublicKeyPath);
bool retrieveGlobalSharingKey(const string &username,
                              const string &userPublicKeyPath,
                              const string &userPrivateKeyPath,
                              const string &userPass,
                              string &globalKey);
bool updateAdminAccessForFile(const string &owner, const string &ownerDerivedKey, const string &globalSharingKey, const string &filePath, const string &clearKeyIV);

#endif // SHARING_KEY_MANAGER_H
