#include "shell.h"
#include "fs_utils.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <sys/stat.h>
#include <dirent.h>

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
static bool isForbiddenCreationDir(const string &normPath, const bool &isAdmin) {
    if (normPath.empty()) return true; // Virtual root
    if (normPath == "shared") return true;
    // admin's allowed modification area is "admin/personal" if base == "filesystem"
    if (isAdmin) {
        // if passed path does not start with "admin/personal"
        if (normPath.find("admin/personal") != 0) {
            return true;
        }
    } else {
        // if passed path does not start with "personal"
        if (normPath.find("personal") != 0) {
            return true;
        }
    }
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
    if (newRel == "XXXFORBIDDENXXX") {
        cout << "Forbidden" << endl;
        return;
    }
    string actual = computeActualPath(base, newRel);
    if (directoryExists(actual)) {
        currentRelative = newRel;
    }
    else
        cout << "Path does Not exist, or is inaccessible." << endl;
}

static void command_pwd(const string &base, const string &currentRelative) {
    if (currentRelative.empty())
        cout << "/" << endl;
    else
        cout << "/" << currentRelative << endl;
}

static void command_ls(const string &base, const string &currentRelative, const string &dirArg) {
    string normPath = normalizePath(base, currentRelative, dirArg);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << "Forbidden" << endl;
        return;
    }
    string dirPath = computeActualPath(base, normPath);
    vector<string> entries;
    if (!listDirectory(dirPath, entries)) {
        cout << "Directory doesn't exist" << endl;
        return;
    }

    for (const auto &name : entries) {

        string fullPath = dirPath + "/" + name;
        struct stat st;
        
        if (name == "." || name == "..")
            cout << "d -> " << name << endl;
        else if (stat(fullPath.c_str(), &st) == 0) {
            if (S_ISDIR(st.st_mode))
                cout << "d -> " << name << endl;
            else
                cout << "f -> " << name << endl;
        }
    }
}

static void command_cat(const string &base, const string &currentRelative, const string &filename) {
    string normPath = normalizePath(base, currentRelative, filename);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << filename << "Forbidden" << endl;
        return;
    }
    string filePath = computeActualPath(base, normPath);
    string contents;
    if (readFile(filePath, contents))
        cout << contents << endl;
    else
        cout << filename << " doesn't exist" << endl;
}

static void command_mkfile(const string &base, const string &currentRelative, const string &filename, const string &contents, const bool &isAdmin) {
    
    string normPath = normalizePath(base, currentRelative, filename);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << filename << "Forbidden" << endl;
        return;
    }
    
    if (isForbiddenCreationDir(normPath, isAdmin)) {
        cout << "Forbidden" << endl;
        return;
    }
    
    string filePath = computeActualPath(base, normPath);
    if (!writeFile(filePath, contents)) {
        cout << "Error creating file" << endl;
    }
}

static void command_mkdir(const string &base, const string &currentRelative, const string &dirname, const bool &isAdmin) {
    
    string normPath = normalizePath(base, currentRelative, dirname);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << "Forbidden" << endl;
        return;
    }

    if (isForbiddenCreationDir(normPath, isAdmin)) {
        cout << "Forbidden" << endl;
        return;
    }
    
    string dirPath = computeActualPath(base, normPath);
    if (directoryExists(dirPath)) {
        cout << "Directory already exists" << endl;
    } else {
        if (!createDirectory(dirPath))
            cout << "Error creating directory" << endl;
    }
}
static void command_share(const string &base, const string &currentRelative, const string &filename, const string &targetUser, const bool &isAdmin) 
{
    string normPath = normalizePath(base, currentRelative, filename);
    if (normPath == "XXXFORBIDDENXXX") {
        cout << filename << " Forbidden" << endl;
        return;
    }

    if (isForbiddenCreationDir(normPath, isAdmin)) {
        cout << "Forbidden" << endl;
        return;
    }

    string sourceFile = computeActualPath(base, normPath);
    if (!fileExists(sourceFile) && !directoryExists(sourceFile)) {
        cout << "File/Directory " << filename << " doesn't exist" << endl;
        return;
    }

    string targetSharedDir = "filesystem/" + targetUser + "/shared";
    if (!directoryExists(targetSharedDir)) {
        cout << "User " << targetUser << " doesn't exist" << endl;
        return;
    }

    string relativeTargetPath = normPath.substr(currentRelative.length() + 1); 
    string targetPath = targetSharedDir + "/" + relativeTargetPath;

    if (fileExists(targetPath) || directoryExists(targetPath)) {
        removeFile(targetPath);
    }

    if (fileExists(sourceFile)) {
        if (!createHardLink(sourceFile, targetPath)) {
            cout << "Error sharing file: " << sourceFile << endl;
        }
    } 
    else if (directoryExists(sourceFile)) {
        if (!directoryExists(targetPath) && !createDirectory(targetPath)) {
            cout << "Failed to create directory: " << targetPath << endl;
            return;
        }

        DIR *dir = opendir(sourceFile.c_str());
        if (!dir) {
            cout << "Failed to open source directory: " << sourceFile << endl;
            return;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != nullptr) {
            if (string(entry->d_name) == "." || string(entry->d_name) == "..") {
                continue;
            }

            string entrySourcePath = sourceFile + "/" + entry->d_name;
            string entryTargetPath = targetPath + "/" + entry->d_name; 

            if (fileExists(entrySourcePath)) {
                if (!createHardLink(entrySourcePath, entryTargetPath)) {
                    cout << "Error sharing file: " << entrySourcePath << endl;
                    closedir(dir);
                    return;
                }
            } 
            else if (directoryExists(entrySourcePath)) {
                command_share(base, currentRelative, normPath + "/" + entry->d_name, targetUser, isAdmin);
            }
        }
        closedir(dir);
    }
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
    string publicKeyfileName = username + "_keyfile";
    string privateKeyfilePath = "filesystem/keyfiles/" + username + "_keyfile";
    if (!writeFile(privateKeyfilePath, username) || !writeFile(publicKeyfileName, username))
        cout << "Error creating keyfiles for " << username << endl;
}

void shellLoop(const string &base, bool isAdmin, const string &currentUser) {
    // currentRelative represents the virtual location relative to the user’s root.
    // For virtual root, we use an empty string ("").
    string currentRelative = "";
    string line;
    while (true) {
        cout << currentRelative << "> ";
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
            string dirArg;
            if (!(iss >> dirArg)) {
                command_ls(base, currentRelative, "");
            } else 
                command_ls(base, currentRelative, dirArg);
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
            command_mkfile(base, currentRelative, filename, contents, isAdmin);
        } else if (command == "mkdir") {
            string dirname;
            if (!(iss >> dirname)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_mkdir(base, currentRelative, dirname, isAdmin);
        } else if (command == "share") {
            string filename, targetUser;
            if (!(iss >> filename >> targetUser)) {
                cout << "Invalid Command" << endl;
                continue;
            }
            command_share(base, currentRelative, filename, targetUser, isAdmin);
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