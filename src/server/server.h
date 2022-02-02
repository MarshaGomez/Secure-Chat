#pragma once
#ifndef SERVER_H
#define SERVER_H

#include "../common/network.h"
#include "../common/utility.h"
#include "../common/params.h"
#include <unordered_map>
#include <pthread.h>
#include <unistd.h>
#include <iostream>
#include <filesystem>
#include <list>
#include <time.h>
#include <regex>
#include <errno.h>
#include <queue>

// OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

// CRYPTO
#include "../common/cryptography.h"

// SEC CODING
#include <limits.h>

using namespace std;

//----------------------------------------------------------
//                    useful objects
//
pthread_mutex_t mutex;          // mutex for accessing global objects
pthread_mutex_t other_mutex;    // other mutex
list<pthread_t> threads;        // list of created threads

enum STATUS {ONLINE, WAITING, CHATTING, QUITTING};



//----------------------------------------------------------
//                      STRUCTs
//
struct Message{
    short message_type;
    char sender[USERNAME_LENGTH+1];
    char receiver[USERNAME_LENGTH+1];
    unsigned int size;
    unsigned char* message;
};

struct MessageBox{
	queue<Message> inQueue;
	queue<Message> outQueue;
	unsigned int sndCount=0;
	unsigned int receiveCount=0;
};

struct Client{
	int socket;
	char username[USERNAME_LENGTH+1];
	char peer_username[USERNAME_LENGTH+1];
	struct MessageBox* mb;
	STATUS status=WAITING;
	unsigned char* sessionKey;
};

//----------------------------------------------------------
//          Server-only Utility functions
//

/**
 * @brief Body of the thread that'll forward a message
 * 
 * @param CLIENT 
 * @return void* 
 */
void *forwardingManager(void *CLIENT);

/**
 * @brief Body of the thread that'll manage the CLIENT's requests
 * 
 * @param CLIENT client to be served
 * @return void* 
 */
void *userManager(void *CLIENT);

/**
 * @brief Get the Client struct
 *
 * @param username username of the client struct that has to be retrieved from the "clients" global object.
 * @return Client*
 */
Client *getClient(const char *username);


/**
 * @brief removes a client struct from the hash table (c++ unordered_map) "clients"
 *
 * @param username username of the client that'll be removed from "clients"
 */
void removeClient(const char *username);


/**
 * @brief Get the server private key
 *
 * @return EVP_PKEY*
 */
EVP_PKEY *get_server_private_key();


/**
 * @brief Get the client pubkey
 *
 * @param username username of the client struct
 * @return EVP_PKEY*
 */
EVP_PKEY *get_client_pubkey(const string username);


/**
 * @brief Appends a thread to the "threads" list
 *
 * @param thread_id pthread_t value
 * @param client pointer to client struct that has been created to represent the state of the real client
 */
void append_thread(pthread_t thread_id, const Client *client);



/**
 * Function that represents the function body of a thread that has to manage the communication with a particular "user".
 * @param param : parameter representing the user that, by using the client program, has just connected to the server
 */
void *thread_body(void *param);


/**
 * @brief Forward messages from a SENDER client to the RECEIVER client
 * 
 */
void forwardMessages();


/**
 * @brief Get the Clients list and sends it to the client that required it
 *
 * @param client client that has required the client list of currently ONLINE clients
 */
void getClientsList(Client *client);


/**
 * @brief Sends RTT to receiver specified in "message"
 *
 * @param client client requesting the send of RTT
 * @param message message containing receiver of the RTT
 * @param ret
 * @param aad
 */
void reqToTalk(Client *client, unsigned char *message, int ret, unsigned char *aad);


/**
 * @brief Sends RTT acceptance reply to receiver specified in "message"
 *
 * @param client client requesting the send of REQUEST_ACCEPTED message
 * @param message message containing receiver of the REQUEST_ACCEPTED message
 * @param client_pubkey public key of client
 * @param aadlen
 * @param aad
 * @param ret
 */
void acceptRTT(Client *client, unsigned char *message, EVP_PKEY *client_pubkey, unsigned int aadlen, unsigned char *aad, int ret);


/**
 * @brief Sends RTT refusal reply to receiver specified in "message"
 *
 * @param client client requesting the send of REQUEST_REFUSED message
 * @param message message containing receiver of the REQUEST_REFUSED message
 */
void refuseRTT(Client *client, const unsigned char *message);


/**
 * @brief Sends encrypted text message from sender client to receiver client
 *
 * @param client Initial sender of encrypted text message
 * @param message message containing receiver of the encrypted message
 * @param aadlen
 * @param aad
 */
void chat(Client *client, unsigned char *message, unsigned int aadlen, unsigned char *aad);


/**
 * @brief Sends CHAT_SESSION message from "client" to receiver described in "message"
 *
 * @param client sending party for the CHAT_SESSION message
 * @param message contains the receiver of the CHAT_SESSION message
 * @param aadlen
 * @param aad
 */
void sendPubKey(Client *client, unsigned char *message, unsigned int aadlen, unsigned char *aad);


/**
 * @brief Updates client structs accordingly to the decision of exiting chat.
 * Decision that is made just by one of two CHATTING clients.
 *
 * @param client client that made the decision of exiting from their current TEXT_MESSAGE session.
 * @param message message containing the receiver of the CHAT_END message
 * @param messageSize
 */
void exitChat(Client *client, unsigned char *message);





//-----------------------------------------------------------
//                  SERVER CLASS                           //
//-----------------------------------------------------------
class Server{
  private :
    /**
     * @value server_sd : socket descriptor of the server
     * @value server_address : struct sockaddr_in of the server
     * @value addrlen : length of "address"
     */
    int server_sd;
    struct sockaddr_in server_address;
    int addrlen;
    /**
    * Method that sets up the struct sockaddr_in "server_address" in the server
    * @param port : port used by the server for communication purposes
    */
    void set_up_server_address(const uint16_t port);

    // Method that initializes the socket descriptor of the server
    void init_server_sd();

  public :
    /**
     * Constructor for the Server class. Sets up all the basic stuff for
     * prepping the server in order to listen for incoming requests from new clients
     * @param port : port used by the server for communication purposes
     */
    Server(const uint16_t port);

    /**
     * getter for "server_sd"
     * @return server_sd
     */
    int get_server_sd() {return this->server_sd;}

    /**
     * getter for "server_address"
     * @return server_address
     */
    sockaddr_in get_server_address(){return this->server_address;}

};

void Server::set_up_server_address(const uint16_t port)
{
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(port);
}

void Server::init_server_sd()
{
    if ((this->server_sd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
        LOG_ERROR("socket() failed");
	fcntl(this->server_sd, F_SETFL, O_NONBLOCK);
}

Server::Server(const uint16_t port)
{
    // initialize socket file descriptor
    init_server_sd();

    this->set_up_server_address(port);
    sockaddr_in server_address = this->get_server_address();
    int addrlen = sizeof(server_address);

    if (inet_pton(AF_INET, LOCALHOST, &server_address.sin_addr) <= 0)
        LOG_ERROR("inet_pton() failed.");

    set_up_server_address(port);

    if (bind(server_sd,(struct sockaddr *)&server_address,sizeof(server_address))<0)
        LOG_ERROR("bind() failed.");
}

#endif