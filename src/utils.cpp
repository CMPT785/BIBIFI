#include "utils.h"
#include "crypto_utils.h" 
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <iomanip>
#include <vector>

using namespace std;



// Helper: Split string by delimiter.
static vector<string> split(const string &s, char delim) {
    vector<string> tokens;
    istringstream iss(s);
    string token;
    while (getline(iss, token, delim)) {
        if (!token.empty())
            tokens.push_back(token);
    }
    return tokens;
}


string toHex(const string &input) {
    ostringstream oss;
    for (unsigned char c : input)
        oss << hex << setw(2) << setfill('0') << (int)c;
    return oss.str();
}

string fromHex(const string &hexString) {
    string output;
    if (hexString.length() % 2 != 0)
        return output; // error: invalid hex string length

    for (size_t i = 0; i < hexString.length(); i += 2) {
        unsigned int byte;
        istringstream iss(hexString.substr(i, 2));
        iss >> hex >> byte;
        output.push_back(static_cast<char>(byte));
    }
    return output;
}

// Encrypt a single file/directory name using the global key.
// The function returns a hex string containing IV + ciphertext.
string encryptName(const string &name, const string &globalKey) {
    // Generate a random IV for this name.
    unsigned char iv[AES_IVLEN];
    if (RAND_bytes(iv, AES_IVLEN) != 1) {
        throw runtime_error("RAND_bytes failed for name encryption");
    }
    // Encrypt the name using AES
    string cipherText = aes_encrypt(name, reinterpret_cast<const unsigned char*>(globalKey.data()), iv);
    // Prepend the IV to the ciphertext and return the hex encoding.
    string combined = string(reinterpret_cast<char*>(iv), AES_IVLEN) + cipherText;
    return toHex(combined);
}

// Decrypt a single file/directory name using the global key.
// The input is expected to be a hex string (IV+ciphertext).
string decryptName(const string &encryptedNameHex, const string &globalKey) {
    // Convert from hex to raw bytes.
    string combined = fromHex(encryptedNameHex);
    if (combined.size() < AES_IVLEN)
        throw runtime_error("Encrypted name too short");
    string iv = combined.substr(0, AES_IVLEN);
    string cipherText = combined.substr(AES_IVLEN);
    return aes_decrypt(cipherText, reinterpret_cast<const unsigned char*>(globalKey.data()), reinterpret_cast<const unsigned char*>(iv.data()));
}

// Split a path (using '/' as separator), encrypt each component, and reassemble.
// For example, "personal/cow.txt" becomes "ENC(partial)/ENC(cow.txt)"
string encryptPath(const string &path, const string &globalKey) {
    vector<string> parts = split(path, '/');
    ostringstream oss;
    bool first = true;
    for (const auto &part : parts) {
        if (part.empty()) continue;
        if (!first)
            oss << "/";
        oss << encryptName(part, globalKey);
        first = false;
    }
    return oss.str();
}

// Decrypt a path by splitting and decrypting each component.
string decryptPath(const string &path, const string &globalKey) {
    vector<string> parts = split(path, '/');
    ostringstream oss;
    bool first = true;
    for (const auto &part : parts) {
        if (part.empty()) continue;
        if (!first)
            oss << "/";
        oss << decryptName(part, globalKey);
        first = false;
    }
    return oss.str();
}