#include "shell.h"
#include "fs_utils.h"
#include "encrypted_fs.h"
#include "crypto_utils.h"
#include "sharing_key_manager.h"
#include "shared_metadata.h"
#include "user_metadata.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <termios.h>
#include <unistd.h>
#include "password_utils.h" // Add this line

using namespace std;

// Helper: trim whitespace.
static string trim(const string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if(start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Function to extract filename from a path and remove ".pem" if present
string get_filename(string path) {
    // Find the last '/'
    size_t lastSlash = path.find_last_of("/");
    if (lastSlash != string::npos) {
        path = path.substr(lastSlash + 1); // Get substring after the last '/'
    }

    // Remove ".pem" extension if present
    if (path.size() > 4 && path.substr(path.size() - 4) == ".pem") {
        path = path.substr(0, path.size() - 4);
    }

    return path;
}

// Initialize a regular user's filesystem by creating "personal" and "shared" directories.
static void initializeUserFilesystem(const string &userDir) {
    if(!createDirectory(userDir + "/personal")){
        cerr << "Error creating personal directory" << endl;
    }
    if(!createDirectory(userDir + "/shared")){
        cerr << "Error creating shared directory" << endl;
    }
}

int main(int argc, char* argv[]) {

    // Ensure required directories exist.
    if (!directoryExists("filesystem")) {
        if (!createDirectory("filesystem")) {
            cerr << "Error creating filesystem directory" << endl;
            return 1;
        }
    }
    if (!directoryExists("public_keys")) {
        if (!createDirectory("public_keys")) {
            cerr << "Error creating filesystem directory" << endl;
            return 1;
        }
    }
    if (!directoryExists("filesystem/keyfiles")) {
        if (!createDirectory("filesystem/keyfiles")) {
            cerr << "Error creating keyfiles directory" << endl;
            return 1;
        }
    }
    if (!directoryExists("filesystem/metadata")) {
        if (!createDirectory("filesystem/metadata")) {
            cerr << "Error creating metadata directory" << endl;
            return 1;
        }
    }
    
    // Admin creation:
    // If admin does not exist, create admin.
    string adminPassphrase;
    bool adminExists = fileExists("filesystem/keyfiles/admin_keyfile.pem");
    if (!adminExists) {
        adminPassphrase = generateRandomPassphrase();
        string privPath = "filesystem/keyfiles/admin_keyfile.pem";
        string pubPath = "public_keys/admin_keyfile.pem";
        if (!generate_rsa_keypair(privPath, pubPath, adminPassphrase)) {
            cerr << "Error creating admin keyfiles" << endl;
            return 1;
        }
        if (!directoryExists("filesystem/admin"))
            if (!createDirectory("filesystem/admin")){
                cerr << "Error admin directory" << endl;
                return 1;
            }
        initializeUserFilesystem("filesystem/admin");


        cout << "Admin user created." <<endl 
            << "Temporary password is: " << adminPassphrase <<endl
            <<" (Record your temporary admin password securely.)" << endl
            << "Please reset password with: changepass <old_password> <new_password>" << endl;

        cout << endl << "Thank you, please login again as admin using the public key." << endl;
        cout << "./fileserver public_keys/admin_keyfile.pem" << endl;
        return 0;
    }
    
    // Prompt for login.
    cout << "Enter username: ";
    string username;
    getline(cin, username);
    username = trim(username);
    if (username.empty()) {
        cerr << "Username cannot be empty." << endl;
        return 1;
    }
    cout << "Enter passphrase for " << username << ": ";
    string userPass = getHiddenPassword();
    userPass = trim(userPass);
    if (userPass.empty()) {
        cerr << "Passphrase cannot be empty." << endl;
        return 1;
    }
    
    // Load the user's private key using the entered passphrase.
    string userPrivKeyPath = "filesystem/keyfiles/" + username + "_keyfile.pem";
    RSA* rsa = load_private_key(userPrivKeyPath, userPass);
    if (!rsa) {
        cout << "Failed to load your private key. Possibly incorrect user or incorrect passphrase." << endl;
        return 1;
    }
    RSA_free(rsa);
    
    // Perform challenge-response authentication.
    if (argc != 2) {
        cerr << "Usage: ./fileserver <public_key_file>" << endl;
        return 1;
    }
    string loginPublicKeyFile = "public_keys/" + get_filename(string(argv[1])) + ".pem";
    ifstream pubKeyStream(loginPublicKeyFile);
    if (!pubKeyStream) {
        cout << "Invalid public key file" << endl;
        return 1;
    }
    string pubKeyContent, line;
    while (getline(pubKeyStream, line))
        pubKeyContent += line + "\n";
    pubKeyStream.close();
    
    // Verify if public and private key match
    if (!verifyKeyPair(loginPublicKeyFile, userPrivKeyPath, userPass)) {
        cout << "The provided public and private keys do not match." << endl;
        return 1;
    }
    
    if (!authenticateUser(username, loginPublicKeyFile, userPrivKeyPath, userPass)) {
        cout << "Authentication failed: public and private keys do not match." << endl;
        return 1;
    }
    
    // Derive a key from the user's password to decrypt their metadata.
    string userDerivedKey = deriveKeyFromPassword(userPass);
    
    // Ensure the user's metadata directory exists.
    string metaDir = "filesystem/metadata/" + username;
    if (!directoryExists(metaDir))
        createDirectory(metaDir);

    // Global Sharing Key:
    // For admin, initialize the global key using admin credentials.
    // For non-admin users, the global key file should already exist wrapped.
    string globalSharingKey;
    if (username == "admin") {
        if (!initGlobalSharingKey("public_keys/admin_keyfile.pem", "filesystem/keyfiles/admin_keyfile.pem", userPass, globalSharingKey)) {
            cerr << "Failed to initialize global sharing key." << endl;
            return 1;
        }
        // For admin, retrieve the global key by unwrapping it.
        if (!retrieveGlobalSharingKey("admin", "public_keys/admin_keyfile.pem", "filesystem/keyfiles/admin_keyfile.pem", userPass, globalSharingKey)) {
            cerr << "Failed to retrieve global sharing key for admin." << endl;
            return 1;
        }
    } else {
        // For non-admin users, retrieve their wrapped copy.
        if (!retrieveGlobalSharingKey(username, loginPublicKeyFile, userPrivKeyPath, userPass, globalSharingKey)) {
            cerr << "Failed to retrieve global sharing key for user " << username << endl;
            return 1;
        }
    }

    // Load the user's envelope metadata.
    vector<EnvelopeEntry> userEnvelopes;
    if (!loadUserMetadata(username, userDerivedKey, userEnvelopes)) {
        cerr << "Failed to load your envelope metadata." << endl;
        return 1;
    }
    
    // Determine the user's base filesystem directory.
    string base;
    if (username == "admin")
        base = "filesystem";
    else {
        base = "filesystem/" + username;
        if (!directoryExists(base)) {
            cout << "User directory not found" << endl;
            return 1;
        }
    }
    
    cout << "Logged in as " << username << endl;
    cout << "Available commands: cd, pwd, ls, cat, share, mkdir, mkfile, changepass, exit";
    if (username == "admin")
        cout << ", adduser";
    cout << endl;

    shellLoop(base, (username == "admin"), username, userPass, globalSharingKey, userDerivedKey);
    return 0;
}
