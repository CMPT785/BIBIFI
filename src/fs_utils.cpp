#include "fs_utils.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <iostream>

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

bool fileExists(const string &path) {
    struct stat st;
    return (stat(path.c_str(), &st) == 0) && S_ISREG(st.st_mode);
}

bool directoryExists(const string &path) {
    struct stat st;
    return (stat(path.c_str(), &st) == 0) && S_ISDIR(st.st_mode);
}

bool createDirectory(const string &path) {
    // mode 0755
    if(mkdir(path.c_str(), 0755) == 0)
        return true;
    if(errno == EEXIST)
        return directoryExists(path);
    return false;
}

bool createDirectories(const string &path) {
    // Create recursively by splitting on '/'
    if(path.empty())
        return false;
    vector<string> parts = split(path, '/');
    string current;
    if(path[0] == '/') {
        current = "/";
    }
    for (size_t i = 0; i < parts.size(); i++) {
        if (!current.empty() && current != "/")
            current += "/";
        current += parts[i];
        if (!directoryExists(current)) {
            if (!createDirectory(current))
                return false;
        }
    }
    return true;
}

bool listDirectory(const string &path, vector<string> &entries) {
    DIR *dir = opendir(path.c_str());
    if (!dir)
        return false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Skip the "." and ".." entries if you wish, but here we return them.
        entries.push_back(string(entry->d_name));
    }
    closedir(dir);
    return true;
}

bool isDirectory(const string &path) {
    return directoryExists(path);
}

bool readFile(const string &path, string &contents) {
    ifstream infile(path);
    if (!infile)
        return false;
    ostringstream oss;
    oss << infile.rdbuf();
    contents = oss.str();
    return true;
}

bool writeFile(const string &path, const string &contents) {
    ofstream outfile(path, ios::trunc);
    if (!outfile)
        return false;
    outfile << contents;
    return true;
}

bool removeFile(const string &path) {
    return (unlink(path.c_str()) == 0);
}

bool createHardLink(const string &existing, const string &newLink) {
    return (link(existing.c_str(), newLink.c_str()) == 0);
}

// Normalize path by handling '.' and '..'.  base is not modified but is the prefix used for absolute paths.
string normalizePath(const string &base, const string &currentRelative, const string &inputPath) {
    vector<string> tokens;
    // If inputPath starts with '/', then start from base.
    if (!inputPath.empty() && inputPath[0] == '/') {
        tokens = split(inputPath, '/');
    } else {
        // Start from currentRelative (which is relative to base)
        if (!currentRelative.empty())
            tokens = split(currentRelative, '/');
        vector<string> relTokens = split(inputPath, '/');
        tokens.insert(tokens.end(), relTokens.begin(), relTokens.end());
    }
    // Process tokens to resolve "." and ".."
    vector<string> result;
    for (const auto &token : tokens) {
        if (token == ".")
            continue;
        if (token == "..") {
            if (!result.empty())
                result.pop_back();
            // If result is empty, remain empty (can't go above virtual root)
        } else {
            result.push_back(token);
        }
    }
    // Rebuild path. If result is empty, return empty string (representing virtual root).
    string normalized;
    for (size_t i = 0; i < result.size(); i++) {
        normalized += result[i];
        if (i < result.size() - 1)
            normalized += "/";
    }
    return normalized;
}
