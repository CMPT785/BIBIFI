#include "password_utils.h"
#include <termios.h>
#include <unistd.h>
#include <string>

std::string getHiddenPassword() {
    termios oldt, newt;
    std::string password;
    char ch;

    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while ((ch = getchar()) != '\n' && ch != EOF)
        password += ch;

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return password;
}
