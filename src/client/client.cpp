#include "client.h"

Client::Client()
{
}

Client::Client(const std::string username)
{
    this->username.assign(username);
}

Client::~Client()
{
}

void Client::setUsername(const std::string username)
{
    this->username.assign(username);
}

void Client::showMenu()
{
    std::string option;
    std::cout << std::endl;
    std::cout << "For show this menu information, type !help" << std::endl;
    std::cout << "Also, you can type COMMAND-NAME directly" << std::endl;
    std::cout << std::endl;
    std::cout << "   COMMAND-NAME            Description" << std::endl;
    std::cout << "   ------------            ------------" << std::endl;
    std::cout << "   !userlist                Displays a list of users currently connected." << std::endl;
    std::cout << "   !startchat <USERNAME>    Start a new conversation with one of the available users." << std::endl;
    std::cout << "   !help                    Displays the explanation of all the possible commands. Help menu." << std::endl;
    std::cout << "   !exit                    Exits the chat secure message application or session that you\'re currently working in." << std::endl;
    std::cout << std::endl;
}

void Client::showLogIn()
{
    int validName;
    std::string username;

    system("clear");

    std::cout << "**********************************************" << std::endl;
    std::cout << "       WELCOME TO SECURITY MESSAGE TEXT_MESSAGE       " << std::endl;
    std::cout << "**********************************************" << std::endl;

    std::cout << "Log in with your credentials" << std::endl
              << std::endl;

    do
    {
        username = readStringValue("Username: ");
        validName = usernameCheck(username);
        if (validName == 1)
        {
            std::cout
                << "ERROR: Invalid user name. The user name can contain any of the following characters   Aa-Zz   0-9   _  "
                << std::endl;
        }
        else if (validName == 2)
        {
            std::cout
                << "ERROR: We couldn\'t log you in. If you don\'t have an account yet, you can contact the Administrator."
                << std::endl;
        }
    } while (validName != 0);

    setUsername(username);
}

void Client::help()
{
    showMenu();
}

std::string Client::getUsername()
{
    return this->username;
}

std::string Client::readPassword()
{
    std::string password;
    std::cout << "Password: ";
    setStdinEcho(false);
    std::cin >> password;
    std::cin.ignore();
    setStdinEcho(true);
    std::cout << std::endl;
    return password;
}