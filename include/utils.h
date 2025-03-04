#ifndef UTILS_H
#define UTILS_H

#include <string>

using namespace std;

// Bytes to Hex
string toHex(const string &input);
string fromHex(const string &hexString);

// Encrypt a single file/directory name using the global key.
// The function returns a hex string containing IV + ciphertext.
string encryptName(const string &name, const string &globalKey);

// Decrypt a single file/directory name using the global key.
// The input is expected to be a hex string (IV+ciphertext).
string decryptName(const string &encryptedNameHex, const string &globalKey);

// Split a path (using '/' as separator), encrypt each component, and reassemble.
// For example, "personal/cow.txt" becomes "ENC(partial)/ENC(cow.txt)"
string encryptPath(const string &path, const string &globalKey);

// Decrypt a path by splitting and decrypting each component.
string decryptPath(const string &path, const string &globalKey);

#endif // UTILS_H
