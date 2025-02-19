#ifndef FS_UTILS_H
#define FS_UTILS_H

#include <string>
#include <vector>

using namespace std;

// Check if a file exists.
bool fileExists(const string &path);

// Check if a directory exists.
bool directoryExists(const string &path);

// Create a directory. Returns true on success.
bool createDirectory(const string &path);

// Recursively create directories (like mkdir -p). Returns true on success.
bool createDirectories(const string &path);

// List the names of entries (files and directories) in a directory.
bool listDirectory(const string &path, vector<string> &entries);

// Check if the given path is a directory.
bool isDirectory(const string &path);

// Read the entire contents of a file into the string 'contents'. Returns true on success.
bool readFile(const string &path, string &contents);

// Write 'contents' to a file (overwriting if it exists). Returns true on success.
bool writeFile(const string &path, const string &contents);

// Remove a file.
bool removeFile(const string &path);

// Create a hard link from 'existing' to 'newLink'. Returns true on success.
bool createHardLink(const string &existing, const string &newLink);

// Normalize and resolve a path given a base directory, the current relative path, and an input path.
// If the input path begins with '/', it is taken as absolute (relative to the user’s virtual root).
// Otherwise, it is relative to the currentRelative path.
string normalizePath(const string &base, const string &currentRelative, const string &inputPath);

#endif // FS_UTILS_H
