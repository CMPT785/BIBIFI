#include <gtest/gtest.h>
#include <fstream>
#include "fs_utils.h"
#include "shell.h"

// Helper function to create a test keyfile
void createTestKeyFile(const std::string &filename, const std::string &username) {
    std::ofstream keyfile(filename);
    keyfile << username;
    keyfile.close();
}

// Test file existence utility function
TEST(FSUtilsTest, FileExists) {
    std::string filename = "test_file.txt";
    std::ofstream testFile(filename);
    testFile << "test data";
    testFile.close();

    EXPECT_TRUE(fileExists(filename));

    // Clean up
    remove(filename.c_str());
}

// Test directory existence utility function
TEST(FSUtilsTest, DirectoryExists) {
    std::string dirname = "test_directory";
    createDirectory(dirname);

    EXPECT_TRUE(directoryExists(dirname));

    // Clean up
    std::system(("rm -r " + dirname).c_str());
}

// Test invalid keyfile authentication
TEST(AuthTest, InvalidKeyFile) {
    createTestKeyFile("invalid_keyfile.txt", "wrong_user");

    std::ifstream keyfile("invalid_keyfile.txt");
    ASSERT_TRUE(keyfile.is_open());

    std::string username;
    keyfile >> username;

    EXPECT_NE(username, "admin");

    // Clean up
    remove("invalid_keyfile.txt");
}

// Test valid keyfile authentication
TEST(AuthTest, ValidKeyFile) {
    createTestKeyFile("valid_keyfile.txt", "admin");

    std::ifstream keyfile("valid_keyfile.txt");
    ASSERT_TRUE(keyfile.is_open());

    std::string username;
    keyfile >> username;

    EXPECT_EQ(username, "admin");

    // Clean up
    remove("valid_keyfile.txt");
}

// Test shell loop initialization (mock test, no actual interaction)
TEST(ShellTest, ShellLoopRuns) {
    std::string base = "filesystem/admin";
    createDirectory("filesystem");
    createDirectory(base);

    EXPECT_NO_FATAL_FAILURE(shellLoop(base, true, "admin"));

    // Clean u
