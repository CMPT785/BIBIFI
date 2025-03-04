#ifndef ENCRYPTED_FS_H
#define ENCRYPTED_FS_H

#include <string>

using namespace std;


// Encrypts and writes the file content to 'path'.
// - 'plaintext': the clear text content of the file.
// - 'ownerUsername': the name of the file's owner.
// - 'ownerDerivedKey': the key derived from the owner's passphrase (used to encrypt metadata).
// - 'globalSharingKey': the global key used for sharing (used to update admin access).
// Returns true on success, false otherwise.
bool encryptedWriteFile(const string &path,
                          const string &plaintext,
                          const string &ownerUsername,
                          const string &ownerDerivedKey,
                          const string &globalSharingKey);

// Reads and decrypts a file from 'path'.
// - 'plaintext': will contain the decrypted file content upon success.
// - 'username': the name of the user reading the file.
// - 'passphrase': the user's passphrase, used to unlock their private key.
// - 'derivedKey': the key derived from the user's passphrase (used for metadata decryption).
// - 'globalKey': the global sharing key (used if the file was shared).
// Returns true on success, false otherwise.
bool encryptedReadFile(const string &path,
                         string &plaintext,
                         const string &username,
                         const string &passphrase,
                         const string &derivedKey,
                         const string &globalKey);

// Unused: Reads and decrypts a global metadata file (like global_sharing.key or a shared_envelopes.enc file)
// using the global sharing key. Returns true on success.
bool readGlobalMetadataFile(const string &path, const string &globalKey, string &plaintext);

#endif // ENCRYPTED_FS_H
