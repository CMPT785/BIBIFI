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
    string keyfileName = argv[1];
    ifstream keyfile(keyfileName);
    if (!keyfile) {
        cout << "Invalid keyfile" << endl;
        return 1;
    }
    string username;
    keyfile >> username;
    username = trim(username);
    if (username.empty()) {
        cout << "Invalid keyfile" << endl;
        return 1;
    }

    // Ensure that the top-level "filesystem" directory exists.
    if (!directoryExists("filesystem")) {
        if (!createDirectory("filesystem")) {
            cerr << "Error creating filesystem directory" << endl;
            return 1;
        }
    }

    // Auto-create the admin keyfile if it doesn't exist.
    if (!fileExists("filesystem/admin_keyfile")) {
        // Create the admin keyfile in the filesystem.
        if (!writeFile("filesystem/admin_keyfile", "admin")) {
            cerr << "Error creating admin_keyfile" << endl;
            return 1;
        }
        // Optionally, create the admin's user directory as well.
        if (!directoryExists("filesystem/admin")) {
            if (!createDirectory("filesystem/admin")) {
                cerr << "Error creating admin user directory" << endl;
                return 1;
            }
            // You can also initialize admin's subdirectories if needed.
            initializeUserFilesystem("filesystem/admin");
        }
    }

    bool isAdmin = (username == "admin");
    string base;

    if (isAdmin) {
        // For admin, the base is the entire "filesystem" directory.
        base = "filesystem";
        // Ensure admin_keyfile exists in the filesystem.
        if (!fileExists(base + "/admin_keyfile")) {
            writeFile(base + "/admin_keyfile", "admin");
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

    // Vulnerable code block: Buffer overflow
    char buffer[10];
    cout << "Enter a string: ";
    cin >> buffer; // This can cause a buffer overflow if input is longer than 9 characters
    cout << "You entered: " << buffer << endl;

    shellLoop(base, isAdmin, username);
    return 0;
}
