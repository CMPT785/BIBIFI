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

void test_cd() {
    // Initial state
    assert(pwd() == "/");

    // Change to personal directory
    cd("personal");
    assert(pwd() == "/personal");

    // Change to shared directory
    cd("/shared");
    assert(pwd() == "/shared");

    // Change to parent directory
    cd("..");
    assert(pwd() == "/");

    // Change to nested directories
    cd("personal/docs");
    assert(pwd() == "/personal/docs");

    // Invalid directory
    cd("invalid");
    assert(pwd() == "/personal/docs");

    cout << "test_cd passed." << endl;
}

void test_ls() {
    // Initial state
    cd("/");
    vector<string> entries;
    assert(ls(entries));

    // Should contain personal and shared directories
    bool foundPersonal = false;
    bool foundShared = false;
    for (const auto &entry : entries) {
        if (entry == "personal")
            foundPersonal = true;
        if (entry == "shared")
            foundShared = true;
    }
    assert(foundPersonal);
    assert(foundShared);

    cout << "test_ls passed." << endl;
}

void test_cat() {
    // Create a test file
    string testFile = "/personal/test_file.txt";
    string content = "Hello, ESFS!";
    writeFile(testFile, content);

    // Read the file
    string readContent;
    assert(cat(testFile, readContent));
    assert(readContent == content);

    // Non-existent file
    assert(!cat("/personal/nonexistent.txt", readContent));

    cout << "test_cat passed." << endl;
}

void test_share() {
    // Create a test file and share it
    string testFile = "/personal/test_file.txt";
    string content = "Hello, ESFS!";
    writeFile(testFile, content);

    // Share the file
    string targetUser = "user2";
    assert(share(testFile, targetUser));

    // Check shared file contents
    string sharedFile = "/shared/" + targetUser + "/test_file.txt";
    string readContent;
    assert(cat(sharedFile, readContent));
    assert(readContent == content);

    cout << "test_share passed." << endl;
}

void test_mkdir() {
    // Create a new directory
    string newDir = "/personal/new_dir";
    assert(mkdir(newDir));
    assert(directoryExists(newDir));

    // Existing directory
    assert(!mkdir(newDir));

    cout << "test_mkdir passed." << endl;
}

void test_mkfile() {
    // Create a new file
    string testFile = "/personal/test_file.txt";
    string content = "Hello, ESFS!";
    assert(mkfile(testFile, content));
    assert(fileExists(testFile));

    // Replace existing file contents
    string newContent = "Updated content.";
    assert(mkfile(testFile, newContent));
    string readContent;
    assert(cat(testFile, readContent));
    assert(readContent == newContent);

    cout << "test_mkfile passed." << endl;
}

void test_adduser() {
    // Add a new user
    string newUser = "new_user";
    assert(adduser(newUser));

    // Existing user
    assert(!adduser(newUser));

    cout << "test_adduser passed." << endl;
}

void runAllTests() {
    
        test_cd();
        test_ls();
        test_cat();
        test_share();
        test_mkdir();
        test_mkfile();
        test_adduser
    test_normalizePath();
    test_fileOperations();
    test_directoryOperations();
    cout << "All tests passed." << endl;
}

int main() {
    runAllTests();
    return 0;
}
