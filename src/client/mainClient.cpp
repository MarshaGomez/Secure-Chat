#include "client.h"
#include "../common/cryptography.h"

Cryptography *crypto;
Client *client;
Network *network;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t dhmutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t waitMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t condition = PTHREAD_COND_INITIALIZER;

volatile sig_atomic_t logged = 0;
int sockfd;

void handleExited(int s)
{

    if (logged == 0)
    {
        setStdinEcho(true);
        exit(1); // if user didn't type credential exit directly!
    }

    std::string username = client->getUsername();

    unsigned char *buffer = allocateValue(buffer, MAX_SIZE);
    unsigned char *message = allocateValue(message, MAX_SIZE);
    unsigned char *aad = allocateValue(aad, MAX_SIZE);

    if (*crypto->crypto_evp->chatting)
    {
        std::cout << "Exited" << std::endl;
        std::cout << "Press enter to continue ..." << std::endl;

        *crypto->crypto_evp->chatting = false;
        *crypto->crypto_evp->waiting = false;
        *crypto->crypto_evp->pending = false;
        *crypto->crypto_evp->done = false;

        crypto->onChatting("!exit", buffer, aad, message);
        free(buffer);
        free(message);
        free(aad);
    }
    else
    {
        crypto->onExit(username, buffer);
        std::cout << "Exited" << std::endl;
        client->~Client();
        network->~Network();
        crypto->~Cryptography();
        close(sockfd);
        free(buffer);
        free(message);
        free(aad);
        exit(1);
    }
}

void *recv_handler(void *arguments)
{
    // CryptoEVP *argumentCTX = crypto->crypto_evp;

    struct CryptoEVP *argumentCTX = (struct CryptoEVP *)arguments;

    unsigned int *srv_recv_counter = argumentCTX->server_receive;
    unsigned int *srv_send_counter = argumentCTX->server_send;
    unsigned int *clt_recv_counter = argumentCTX->client_receive;
    unsigned int *clt_send_counter = argumentCTX->client_send;
    unsigned char *server_sessionkey = argumentCTX->cs_session_key;
    unsigned char *client_sessionkey = argumentCTX->cc_session_key;
    unsigned char *nonce = argumentCTX->storedNonce;
    char *peer_username = argumentCTX->peer;
    bool *pending = argumentCTX->pending;
    bool *chatting = argumentCTX->chatting;
    bool *doneptr = argumentCTX->done;
    bool *waiting = argumentCTX->waiting;
    short *message_type = argumentCTX->message_type;

    EVP_PKEY *user_key = argumentCTX->user_key;
    std::string username = client->getUsername();

    unsigned char *message = allocateValue(message, MAX_SIZE);
    unsigned char *buffer = allocateValue(buffer, MAX_SIZE);
    unsigned char *aad = allocateValue(aad, MAX_SIZE);

    int message_size;
    int ret;
    unsigned int aadlen;
    bool done = *doneptr;

    while (!done)
    {
        pthread_mutex_lock(&dhmutex);
        while (*pending)
        {
            pthread_cond_wait(&condition, &dhmutex);
        }
        pthread_mutex_unlock(&dhmutex);
        sockfd = network->getSockFD();
        message_size = crypto->receiveMessage(sockfd, buffer);
        if (message_size > 0)
        {
            unsigned int received_counter = *(unsigned int *)(buffer + MSGHEADER);
            if (received_counter == *srv_recv_counter)
            {

                memset(message, 0, message_size);
                ret = crypto->authDecrypt(buffer, message_size, server_sessionkey, *message_type, aad, aadlen, message);

                if (ret >= 0)
                {
                    crypto->safeIncrement(*srv_recv_counter);

                    pthread_mutex_lock(&waitMutex);
                    switch (*message_type)
                    {

                    case ONLINE_USERS:
                    {
                        crypto->getUserList(message);
                        break;
                    }
                    case REQUEST_TO_TALK:
                    {
                        crypto->requestMessage(ret, message, aad);
                        break;
                    }
                    case REQUEST_ACCEPTED:
                    {
                        crypto->acceptMessage(ret, buffer, message, aad, aadlen);
                        break;
                    }
                    case REQUEST_REFUSED:
                    {
                        crypto->refuseMessage(ret, message);
                        break;
                    }
                    case TEXT_MESSAGE:
                    {
                        crypto->chatMessage(ret, username, buffer, message, message_size, aad, aadlen);
                        break;
                    }
                    case UNKNOWN_USER:
                    {
                        crypto->userNotFound();
                        break;
                    }
                    case CHAT_CLOSED:
                    {
                        crypto->closeChat(ret, message);
                        break;
                    }
                    }
                    pthread_mutex_unlock(&waitMutex);
                }
            }
        }
        done = *doneptr;
    }
    free(buffer);
    free(message);
    free(aad);
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{

    // Ctrl + C Exited
    signal(SIGINT, handleExited);
    // Ctrl + Z Exited
    signal(SIGTSTP, handleExited);

    try
    {
        int port, ret;
        char *host;
        struct sockaddr_in serv_addr;
        unsigned int message_size;
        char messageInput[MSG_MAX];

        client = new Client("");
        network = new Network(0, (char *)' ', SOCK_STREAM);
        crypto = new Cryptography();

        network->clientConnection(argc, argv);

        sockfd = network->getSockFD();

        EVP_PKEY *user_key;
        unsigned char *message = allocateValue(message, MAX_SIZE);
        unsigned char *buffer = allocateValue(buffer, MAX_SIZE);
        unsigned char *aad = allocateValue(aad, MAX_SIZE);

        client->showLogIn();

        std::string username = client->getUsername();
        std::string password = client->readPassword();
        logged = 1;

        crypto->readPrivateKey(username, password, user_key);

        // Send nonce and username
        unsigned char *userNonce = crypto->newNonce();

        memcpy(buffer, userNonce, NONCE_SIZE);
        memcpy(buffer + NONCE_SIZE, username.c_str(), username.length());

        unsigned int signed_size = crypto->digsignSign(user_key, buffer, NONCE_SIZE + username.length(), message);
        crypto->sendMessage(sockfd, signed_size, message);

        unsigned char *certbuffer = allocateValue(certbuffer, MAX_SIZE);

        long certsize = receiveMessage(sockfd, certbuffer);

        EVP_PKEY *server_pubkey = crypto->checkServerCertificate(certbuffer, certsize);

        signed_size = crypto->receiveMessage(sockfd, buffer);
        if (signed_size <= 0)
        {
            std::cerr << "receive message: error";
            exit(1);
        }
        unsigned int signature_size = *(unsigned int *)buffer;
        signature_size += sizeof(unsigned int);
        if (memcmp(buffer + signature_size, userNonce, NONCE_SIZE) != 0)
        {
            std::cerr << "nonce received is not valid!";
            exit(1);
        }
        free(userNonce);
        // verify signature and take server nonce
        message_size = crypto->digsignVerify(server_pubkey, buffer, signed_size, message);
        if (message_size <= 0)
        {
            std::cerr << "signature is invalid";
            exit(1);
        }

        EVP_PKEY *ecdh_server_pubkey;
        EVP_PKEY *ecdh_priv_key = crypto->dhGenerateKey();

        crypto->getServerEphemeralKey(ecdh_server_pubkey, ecdh_priv_key, message, message_size);

        signed_size = crypto->digsignSign(user_key, message, message_size, buffer);
        crypto->sendMessage(sockfd, signed_size, buffer);

        unsigned char *server_sessionkey = allocateValue(server_sessionkey, EVP_MD_size(crypto->md));

        crypto->secretDerivation(ecdh_priv_key, ecdh_server_pubkey, server_sessionkey);

        EVP_PKEY_free(ecdh_server_pubkey);
        EVP_PKEY_free(ecdh_priv_key);

        unsigned int server_receive_counter = 0, srv_counter = 0, client_receive_counter = 0, clt_counter = 0;

        short message_type;

        unsigned int aadlen;
        message_size = crypto->receiveMessage(sockfd, buffer);
        unsigned int received_counter = *(unsigned int *)(buffer + MSGHEADER);

        if (received_counter == server_receive_counter)
        {
            ret = crypto->authDecrypt(buffer, message_size, server_sessionkey, message_type, aad, aadlen, message);
            crypto->safeIncrement(server_receive_counter);
        }

        std::string command;
        bool done = false;
        bool chatting = false;
        bool pending = false;
        bool waiting = false;
        unsigned char *client_sessionkey = allocateValue(client_sessionkey, EVP_MD_size(crypto->md));

        pthread_t receiver;
        char peer_username[USERNAME_LENGTH + 1];
        unsigned char *nonce = allocateValue(nonce, NONCE_SIZE);

        crypto->crypto_evp->server_receive = &server_receive_counter;
        crypto->crypto_evp->client_send = &clt_counter;
        crypto->crypto_evp->server_send = &srv_counter;
        crypto->crypto_evp->client_receive = &client_receive_counter;
        crypto->crypto_evp->cs_session_key = server_sessionkey;
        crypto->crypto_evp->cc_session_key = client_sessionkey;
        crypto->crypto_evp->storedNonce = nonce;
        crypto->crypto_evp->user_key = user_key;
        crypto->crypto_evp->peer = peer_username;
        crypto->crypto_evp->done = &done;
        crypto->crypto_evp->chatting = &chatting;
        crypto->crypto_evp->pending = &pending;
        crypto->crypto_evp->waiting = &waiting;
        crypto->crypto_evp->message_type = &message_type;
        crypto->crypto_evp->sockfd = sockfd;

        client->showMenu();

        if (pthread_create(&receiver, NULL, &recv_handler, (void *)crypto->crypto_evp) != 0)
            std::cout << "Failed to create thread" << std::endl;

        while (!done)
        {
            pthread_mutex_init(&waitMutex, 0);
            usleep(60000);

            if (chatting)
            {
                std::cout << "\r" << capitalize(username) << ": ";
                bzero(messageInput, MSG_MAX);
                std::cin.getline(messageInput, MSG_MAX);
                command.assign(messageInput);
            }
            else
            {
                std::cout << "\033[32m"
                          << username << "@secure-chat"
                          << "\033[0m"
                          << "$ ";

                getline(std::cin, command);
            }

            if (!waiting && !chatting)
            {
                if (pending)
                {
                    if (command.compare("!accept") == 0)
                    {
                        crypto->onAccept(buffer, message, aad, aadlen);
                        pthread_mutex_lock(&dhmutex);
                        pending = false;
                        chatting = true;
                        pthread_cond_signal(&condition);
                        pthread_mutex_unlock(&dhmutex);
                        command.assign("has accepted the chat request.", 30);
                    }
                    else if (command.compare("!refuse") == 0)
                    {
                        crypto->onRefuse(buffer);
                        pthread_mutex_lock(&dhmutex);
                        pending = false;
                        pthread_cond_signal(&condition);
                        pthread_mutex_unlock(&dhmutex);
                        client->showMenu();
                    }
                    else
                    {
                        crypto->showNewRequestMenu();
                    }
                }
                else if (command.compare("!help") == 0)
                {
                    client->help();
                }
                else if (command.compare("!userlist") == 0)
                {
                    crypto->onUserList(username, buffer);
                }
                else if (command.compare(0, 11, "!startchat ") == 0)
                {
                    crypto->onStartChat(command, buffer, aad);
                }
                else if (command.compare("!exit") == 0)
                {
                    crypto->onExit(username, buffer);
                }
                else if (command.size() == 0) {
                }
                else
                {
                    std::cout << "Wrong command." << std::endl;
                }
            }

            if (chatting)
            {
                crypto->onChatting(command, buffer, aad, message);
            }
            pthread_mutex_destroy(&waitMutex);
        }
        pthread_join(receiver, NULL);

        std::cout << "Exited." << std::endl;
        close(sockfd);
        free(server_sessionkey);
        free(client_sessionkey);
        free(buffer);
        free(aad);
        free(message);
        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        exit(1);
    }

    client->~Client();
    crypto->~Cryptography();
    close(sockfd);
    return 0;
}
