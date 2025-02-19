#include "shell.h"
#include "fs_utils.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <sys/stat.h>

using namespace std;

// Helper: trim whitespace.
static string trim(const string &s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if(start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Check if the current relative directory is forbidden for creation commands.
// For non-admin users, creation in the virtual root ("" representing "/") or in "shared" is forbidden.
static bool isForbiddenCreationDir(const string &currentRelative) {
    if (currentRelative.empty()) return true; // Virtual root
    if (currentRelative == "shared") return true;
    return false;
}

// Given a base and a currentRelative (both as strings), compute the actual directory path on disk.
static string computeActualPath(const string &base, const string &currentRelative) {
    if (currentRelative.empty())
        return base;
    else
        return base + "/" + currentRelative;
}

// Command implementations
static void command_cd(const string &base, string &currentRelative, const string &dirArg) {
    string newRel = normalizePath(base, currentRelative, dirArg);
    // Compute actual path on disk.
    string actual = computeActualPath(base, newRel);
    if (directoryExists(actual)) {
        currentRelative = newRel;
    }
    // else, remain in current directory.
}

static void command_pwd(const string &base, const string &currentRelative) {
    if (currentRelative.empty())
        cout << "/" << endl;
    else
        cout << "/" << currentRelative << endl;
}

static void command_ls(const string &base, const string &currentRelative) {
    string dirPath = computeActualPath(base, currentRelative);
    vector<string> entries;
    if (!listDirectory(dirPath, entries)) {
        cout << "Directory doesn't exist" << endl;
        return;
    }

    for (const auto &name : entries) {
        if (name == "." || name == "..")
            cout << "d -> " << name << endl;
        string fullPath = dirPath + "/" + name;
        struct stat st;
        if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode))
                cout << "d -> " << name << endl;
            else
                cout << "f -> " << name << endl;
        }
    }
}

static void command_cat(const string &base, const string &currentRelative, const string &filename) {
    string filePath = computeActualPath(base, currentRelative) + "/" + filename;
    string contents;
    if (readFile(filePath, contents))
        cout << contents << endl;
    else
        cout << filename << " doesn't exist" << endl;
}

static void command_mkfile(const string &base, const string &currentRelative, const string &filename, const string &contents) {
    if (isForbiddenCreationDir(currentRelative)) {
        cout << "Forbidden" << endl;
        return;
    }
    string filePath = computeActualPath(base, currentRelative) + "/" + filename;
    if (!writeFile(filePath, contents)) {
        cout << "Error creating file" << endl;
    }
}

static void command_mkdir(const string &base, const string &currentRelative, const string &dirname) {
    if (isForbiddenCreationDir(currentRelative)) {
        cout << "Forbidden" << endl;
        return;
    }
    string dirPath = computeActualPath(base, currentRelative) + "/" + dirname;
    if (directoryExists(dirPath)) {
        cout << "Directory already exists" << endl;
    } else {
        if (!createDirectory(dirPath))
            cout << "Error creating directory" << endl;
    }
}

static void command_share(const string &base, const string &currentRelative, const string &filename, const string &targetUser) {
    // Source file path.
    string sourceFile = computeActualPath(base, currentRelative) + "/" + filename;
    if (!fileExists(sourceFile)) {
        cout << "File " << filename << " doesn't exist" << endl;
        return;
    }
    // Target user's shared directory: "filesystem/<targetUser>/shared"
    string targetSharedDir = "filesystem/" + targetUser + "/shared";
    if (!directoryExists(targetSharedDir)) {
        cout << "User " << targetUser << " doesn't exist" << endl;
        return;
    }
    string targetLink = targetSharedDir + "/" + filename;
    // If target file exists, remove it.
    if (fileExists(targetLink))
        removeFile(targetLink);
    if (!createHardLink(sourceFile, targetLink))
        cout << "Error sharing file" << endl;
}

static void command_adduser(const string &username) {
    // Check if user already exists by verifying the directory "filesystem/<username>"
    string userDir = "filesystem/" + username;
    if (directoryExists(userDir)) {
        cout << "User " << username << " already exists" << endl;
        return;
    }
    // Create the user's directory structure.
    if (!createDirectories(userDir)) {
        cout << "Error creating user directory" << endl;
        return;
    }
    // Create personal and shared directories.
    if (!createDirectory((userDir + "/personal"))) {
        cout << "Error creating personal directory" << endl;
    }
    if (!createDirectory((userDir + "/shared"))) {
        cout << "Error creating shared directory" << endl;
    }
    // Create the keyfile: <username>_keyfile in the current working directory.
    string keyfileName = username + "_keyfile";
    if (!writeFile(keyfileName, username))
        cout << "Error creating keyfile for " << username << endl;
}

void shellLoop(const string &base, bool isAdmin, const string &currentUser) {
    // currentRelative represents the virtual location relative to the user’s root.
    // For virtual root, we use an empty string ("").
    string currentRelative = "";
    string line;
    while (true) {
        cout << "> ";
        if (!getline(cin, line))
            break;
        line = trim(line);
        if (line.empty())
            continue;
        istringstream iss(line);
        string command;
        iss >> command;
        if (command == "exit") {
            break;
        } else if (command == "cd") {
            string dirArg;
            if (!(iss >> dirArg)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_cd(base, currentRelative, dirArg);
        } else if (command == "pwd") {
            command_pwd(base, currentRelative);
        } else if (command == "ls") {
            command_ls(base, currentRelative);
        } else if (command == "cat") {
            string filename;
            if (!(iss >> filename)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_cat(base, currentRelative, filename);
        } else if (command == "mkfile") {
            string filename;
            if (!(iss >> filename)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            string contents;
            getline(iss, contents);
            contents = trim(contents);
            command_mkfile(base, currentRelative, filename, contents);
        } else if (command == "mkdir") {
            string dirname;
            if (!(iss >> dirname)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_mkdir(base, currentRelative, dirname);
        } else if (command == "share") {
            string filename, targetUser;
            if (!(iss >> filename >> targetUser)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_share(base, currentRelative, filename, targetUser);
        } else if (command == "adduser") {
            if (!isAdmin) {
                cout << "Invalid Command" << endl;
                continue;
            }
            string newUser;
            if (!(iss >> newUser)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_adduser(newUser);
        } else {
            cout << "Invalid Command" << endl;
        }
    }
}
