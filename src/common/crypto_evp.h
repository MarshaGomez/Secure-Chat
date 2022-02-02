// Client manager. Internal library
#pragma once
#ifndef CRYPTOEVP_H
#define CRYPTOEVP_H

#include <openssl/evp.h>

struct CryptoEVP 
{
    unsigned int *server_send;
    unsigned int *client_send;
    unsigned int *server_receive;
    unsigned int *client_receive;
    unsigned char *cs_session_key;
    unsigned char *cc_session_key;
    unsigned char *storedNonce;
    EVP_PKEY *user_key;
    char *peer;
    bool *pending;
    bool *done;
    bool *chatting;
    bool *waiting;
    short *message_type;
    int sockfd;
};

#endif // CRYPTOEVP_H