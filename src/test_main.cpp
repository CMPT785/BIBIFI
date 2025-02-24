#include <gtest/gtest.h>
#include "fs_utils.h"  // Include necessary headers
#include "shell.h"

class FileSystemTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Set up a clean test environment (e.g., create temp directories)
        system("rm -rf test_filesystem && mkdir test_filesystem");  
    }

    void TearDown() override {
        // Cleanup after tests
        system("rm -rf test_filesystem");
    }
};

// ✅ Test Case: Filesystem Initialization
TEST_F(FileSystemTest, InitializeFileSystem) {
    EXPECT_EQ(initializeFilesystem("test_filesystem"), true);
}

// ✅ Test Case: User Authentication
TEST_F(FileSystemTest, AuthenticateUser) {
    createUser("testuser");  // Assume createUser() generates keyfiles
    EXPECT_TRUE(authenticate("testuser_keyfile"));
    EXPECT_FALSE(authenticate("invalid_keyfile"));
}

// ✅ Test Case: Create & Change Directory
TEST_F(FileSystemTest, ChangeDirectory) {
    EXPECT_TRUE(makeDirectory("/personal/testdir"));
    EXPECT_TRUE(changeDirectory("/personal/testdir"));
    EXPECT_FALSE(changeDirectory("/invalid_path"));
}

// ✅ Test Case: Create & Read File
TEST_F(FileSystemTest, FileOperations) {
    createFile("/personal/testfile", "Hello, World!");
    std::string content = readFile("/personal/testfile");
    EXPECT_EQ(content, "Hello, World!");
}

// ✅ Test Case: Share File
TEST_F(FileSystemTest, ShareFile) {
    createUser("userA");
    createUser("userB");
    createFile("/personal/userA/testfile", "Shared Content");
    EXPECT_TRUE(shareFile("/personal/userA/testfile", "userB"));
    std::string sharedContent = readFile("/shared/userB/testfile");
    EXPECT_EQ(sharedContent, "Shared Content");
}

// ✅ Test Case: Invalid Commands
TEST_F(FileSystemTest, InvalidCommands) {
    EXPECT_FALSE(makeDirectory("/invalid"));  // Cannot create in root
    EXPECT_FALSE(createFile("/shared/testfile", "Forbidden"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
