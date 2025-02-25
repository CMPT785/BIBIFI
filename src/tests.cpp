#include "fs_utils.h"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

void test_normalizePath() {
    string base = "filesystem";
    string currentRelative = "personal";
    string input = "docs";
    string expected = "personal/docs";
    string result = normalizePath(base, currentRelative, input);
    assert(result == expected);

    // Test with an absolute path (should ignore currentRelative)
    input = "/personal/docs";
    expected = "personal/docs";
    result = normalizePath(base, currentRelative, input);
    assert(result == expected);

    // Test current directory indicator "."
    input = ".";
    expected = "personal";
    result = normalizePath(base, currentRelative, input);
    assert(result == expected);

    // Test parent directory ".." when possible
    currentRelative = "personal/docs";
    input = "..";
    expected = "personal";
    result = normalizePath(base, currentRelative, input);
    assert(result == expected);

    // Test trying to go above virtual root: expect forbidden.
    currentRelative = "personal";
    input = "..";
    result = normalizePath(base, currentRelative, input);
    assert(result == "XXXFORBIDDENXXX");

    // Test a complex path that should result in forbidden.
    currentRelative = "personal/docs";
    input = "../..";
    result = normalizePath(base, currentRelative, input);
    assert(result == "XXXFORBIDDENXXX");

    cout << "test_normalizePath passed." << endl;
}

void test_fileOperations() {
    // Create a temporary file, write, read, and remove it.
    string testFile = "test_file.txt";
    string content = "Hello, ESFS!";

    bool success = writeFile(testFile, content);
    assert(success);

    string readContent;
    success = readFile(testFile, readContent);
    assert(success);
    assert(readContent == content);

    assert(fileExists(testFile) == true);

    success = removeFile(testFile);
    assert(success);
    assert(fileExists(testFile) == false);

    cout << "test_fileOperations passed." << endl;
}

void test_directoryOperations() {
    // Create a temporary directory structure and test operations.
    string testDir = "test_dir";
    bool success = createDirectory(testDir);
    assert(success);
    assert(directoryExists(testDir) == true);

    // Test recursive directory creation.
    string nestedDir = testDir + "/a/b/c";
    success = createDirectories(nestedDir);
    assert(success);
    assert(directoryExists(nestedDir) == true);

    // Test listing the directory.
    vector<string> entries;
    success = listDirectory(testDir, entries);
    assert(success);
    bool foundA = false;
    for (const auto &entry : entries) {
        if (entry == "a")
            foundA = true;
    }
    assert(foundA);

    cout << "test_directoryOperations passed." << endl;

    // Note: Cleanup of directories isn’t implemented in these tests.
}

void runAllTests() {
    test_normalizePath();
    test_fileOperations();
    test_directoryOperations();
    cout << "All tests passed." << endl;
}

int main() {
    runAllTests();
    return 0;
}