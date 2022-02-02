// Client manager. Internal library
#pragma once
#ifndef CLIENT_H
#define CLIENT_H

#include <signal.h>
#include "../common/params.h"
#include "../common/utility.h"
#include "../common/network.h"
#include "../common/crypto_evp.h"

class Client
{
protected:
    /**
     * @value username: nickname of the client
     */
    std::string username;

public:
    /**
     * Constructor Client
     **/
    Client();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Constructor Client
     * @param username: Name of the Client
     **/
    Client(const std::string username);

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Destructor Client
     **/
    ~Client();
    //------------------------------------------------------------------------------------------------------------------
    /**
     * Setter Username
     * @param username: Name of the Client
     **/
    void setUsername(const std::string username);

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Print the options resume
     **/
    void showMenu();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Displays Log-in message
     **/
    void showLogIn();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Process for option Help
     */
    void help();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Return the username
     **/
    std::string getUsername();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Function for read a valid Password
     **/
    std::string readPassword();
};

#endif // CLIENT_H