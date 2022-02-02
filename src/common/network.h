// Network manager. Internal library
#pragma once
#ifndef NETWORK_H
#define NETWORK_H

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <iostream>
#include <stdexcept>
#include "params.h"
#include "cryptography.h"

class Network
{

protected:
    /**
     * @value socketType: the socket has the indicated type, which specifies the communication semantics.  Currently defined types are: SOCK_STREAM | SOCK_DGRAM | SOCK_SEQPACKET | SOCK_RAW | SOCK_RDM | SOCK_PACKET
     * @value address: this selects the protocol family which will be used for communication.
     * @value sockfd: is the file descriptor of the sending socket.
     * @value port: is the listening port
     */
    int socketType;
    struct sockaddr_in address;
    int sockfd;
    char *host;
    int port;

private:
    /**
     * Return (0) on success and (-1) on error. it waits for one of
       a set of file descriptors to become ready to perform I/O.
    **/
    int waitActivity();

public:
    /**
     *
     */
    Network();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Constructur Network
     * @param socketType to specify the communication semantic.
     * @param port to specify the port communication
     **/
    Network(const int port, char *host, const int socketType);

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Destructor Network
     **/
    ~Network();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void setPort(const int port);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void setHost(char *host);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void setContext(CryptoEVP *crypto_evp);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void newConnection();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Return the socket file descriptor identificator (return int value)
     **/
    void startConnection();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Send Message to Server
     * @param message the message received from the socket
     * @param messageLenght lenght of the incoming message
     **/
    void sendMessage(unsigned char *message, unsigned int messageLenght);



    //------------------------------------------------------------------------------------------------------------------
    /**
     * Show configurated network values
     **/
    void showConfiguration();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void initConfiguration(int argc, char *argv[]);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void clientConnection(int argc, char *argv[]);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    int getPort();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Return the socket file descriptor identificator (return int value)
     **/
    int getSockFD();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    char *getHost();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    CryptoEVP *getContext();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Return the Address protocol family which will be used for communication (return sockaddr_in value)
     **/
    sockaddr_in getAddress();
};

#endif // NETWORK_H
