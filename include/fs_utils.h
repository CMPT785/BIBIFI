#ifndef FS_UTILS_H
#define FS_UTILS_H

#include <string>
#include <vector>

using namespace std;

// File and directory operations
bool fileExists(const string &path);
bool directoryExists(const string &path);
bool createDirectory(const string &path);
bool createDirectories(const string &path);
bool listDirectory(const string &path, vector<string> &entries);
bool isDirectory(const string &path);
bool readFile(const string &path, string &contents);
bool writeFile(const string &path, const string &contents);
bool removeFile(const string &path);
bool createHardLink(const string &existing, const string &newLink);

// Path helper functions
string normalizePath(const string &base, const string &currentRelative, const string &inputPath);

#endif // FS_UTILS_H

