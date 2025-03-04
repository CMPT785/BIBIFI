#ifndef SHELL_H
#define SHELL_H

#include <string>

using namespace std;

// Interactive shell main loop
void shellLoop(const string &base, bool isAdmin, const string &currentUser, const string &userPass, const string &globalSharingKey, const string &userDerivedKey);

#endif // SHELL_H
