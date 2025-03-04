#ifndef SHELL_H
#define SHELL_H

#include <string>

using namespace std;

// Starts the interactive shell loop.
//   base: The base directory for file operations (e.g., "filesystem" for admin or "filesystem/<username>" for a regular user).
//   isAdmin: True if the logged-in user is admin.
//   currentUser: The username of the logged-in user.
void shellLoop(const string &base, bool isAdmin, const string &currentUser);

#endif // SHELL_H
