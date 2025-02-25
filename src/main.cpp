#include "shell.h"
#include "fs_utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

using namespace std;

// Helper: trim whitespace.
static string trim(const string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if(start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Initialize a regular user's filesystem by creating "personal" and "shared" directories.
static void initializeUserFilesystem(const string &userDir) {
    createDirectory(userDir + "/personal");
    createDirectory(userDir + "/shared");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: ./fileserver keyfile_name" << endl;
        return 1;
    }
    string publicKeyFileName = argv[1];
    ifstream public_keyfile(publicKeyFileName);
    if (!public_keyfile) {
        cout << "Invalid keyfile 1" << endl;
        return 1;
    }

    // Ensure that the top-level "filesystem" directory exists.
    if (!directoryExists("filesystem")) {
        if (!createDirectory("filesystem")) {
            cerr << "Error creating filesystem directory" << endl;
            return 1;
        }
    }

    // Ensure the protected keyfiles folder exists.
    if (!directoryExists("filesystem/keyfiles")) {
        if (!createDirectory("filesystem/keyfiles")) {
            cerr << "Error creating keyfiles directory" << endl;
            return 1;
        }
    }

    // Auto-create the admin keyfile and directories if it doesn't exist.
    if (!fileExists("filesystem/keyfiles/admin_keyfile")) {
        if (!writeFile("filesystem/keyfiles/admin_keyfile", "admin")) {
            cerr << "Error creating admin keyfile" << endl;
            return 1;
        }
        // create admin's own directory.
        if (!directoryExists("filesystem/admin")) {
            if (!createDirectory("filesystem/admin")) {
                cerr << "Error creating admin directory" << endl;
                return 1;
            }
            initializeUserFilesystem("filesystem/admin");
        }
    }

    string keyfileName = string("filesystem/keyfiles/") + argv[1];
    ifstream keyfile(keyfileName);
    if (!keyfile) {
        cout << "Invalid keyfile" << endl;
        return 1;
    }

    string username;
    keyfile >> username;
    username = trim(username);
    string passed_username;
    public_keyfile >> passed_username;
    passed_username = trim(passed_username);
    if (username.empty() || passed_username.empty()) {
        cout << "Invalid keyfile" << endl;
        return 1;
    }
    if (username != passed_username) {
        cout << "Authentication Error: public and pirivate keys do Not match" << endl;
        return 1;
    }

    bool isAdmin = (username == "admin");
    string base;

    if (isAdmin) {
        // For admin, the base is the entire "filesystem" directory.
        base = "filesystem";
        // Ensure admin_keyfile exists in the filesystem.
        if (!fileExists(base + "/keyfiles/admin_keyfile")) {
            writeFile(base + "/keyfiles/admin_keyfile", "admin");
        }
    } else {
        // For a regular user, the base is "filesystem/<username>"
        base = "filesystem/" + username;
        if (!directoryExists(base)) {
            cout << "Invalid keyfile" << endl;
            return 1;
        }
        initializeUserFilesystem(base);
    }

    cout << "Logged in as " << username << endl;
    cout << "Available commands: cd, pwd, ls, cat, share, mkdir, mkfile, exit";
    if (isAdmin)
        cout << ", adduser";
    cout << endl;

    shellLoop(base, isAdmin, username);
    return 0;
}
