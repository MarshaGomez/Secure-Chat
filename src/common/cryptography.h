// Security manager. Internal library
#pragma once
#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "utility.h"
#include "crypto_evp.h"

class Cryptography
{
public:
    /**
     * @value AE_cipher:
     * @value AE_iv_len:
     * @value AE_block_size:
     * @value AE_tag_len:
     * @value md:
     * @value crypto_evp:
     **/

    static const EVP_CIPHER *AE_cipher;
    static int AE_iv_len;
    static int AE_block_size;
    static const EVP_MD *md;
    static CryptoEVP *crypto_evp;

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Constructor
     **/
    Cryptography();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Destructor
     **/
    ~Cryptography();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Print the manage error
     **/
    void printError(void);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    void sendMessage(int sockfd, unsigned int msgLength, unsigned char *message);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    void readPrivateKey(const std::string username, const std::string password, EVP_PKEY *&privateKey);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    void getServerEphemeralKey(EVP_PKEY *&peerKey, EVP_PKEY *ecdhPrivateKey, unsigned char *&message, unsigned int &msgLength);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    void loadCertificate(X509 *&cert, const char *path);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    void loadCRL(X509_CRL *&cert, const char *path);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void deserializePublicKey(unsigned char *buffer, unsigned int length, EVP_PKEY *&key);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void secretDerivation(EVP_PKEY *key, EVP_PKEY *peerPubKey, unsigned char *buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Generate Nonce
     */
    void newNonce(unsigned char *nonce);

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Increment Counter in a safe way (Secure Coding INT Bound Checking)
     */
    void safeIncrement(unsigned int &value);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void getPublicKey(X509 *cert, EVP_PKEY *&key);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void acceptMessage(int ret, unsigned char *buffer, unsigned char *message, unsigned char *aad, unsigned int aadlen);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void refuseMessage(int ret, unsigned char *message);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void chatMessage(int ret, std::string username, unsigned char *buffer, unsigned char *message, unsigned int message_size, unsigned char *aad, unsigned int aadlen);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void onAccept(unsigned char *buffer, unsigned char *message, unsigned char *aad, unsigned int aadlen);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void onRefuse(unsigned char *buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void onExit(std::string username, unsigned char *buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void onUserList(std::string username, unsigned char *buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void onStartChat(std::string command, unsigned char *buffer, unsigned char *aad);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void onChatting(std::string command, unsigned char *buffer, unsigned char *aad, unsigned char *message);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void requestMessage(int ret, unsigned char *message, unsigned char *aad);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void showNewRequestMenu();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void getUserList(unsigned char *buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void userNotFound();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    void closeChat(int ret, unsigned char *message);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     */
    unsigned char *newNonce();

    //------------------------------------------------------------------------------------------------------------------
    /**
     * Receive signed message
     * @paramm sockfd
     **/
    unsigned int receiveMessage(int sockfd, unsigned char *message);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    unsigned int
    digsignSign(EVP_PKEY *prvkey, unsigned char *clear_buf, unsigned int clear_size, unsigned char *output_buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    unsigned int
    dhGenerateSessionKey(unsigned char *shared_secret, unsigned int shared_secretlen, unsigned char *sessionkey);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    unsigned int authEncrypt(short message_type, unsigned char *aad, unsigned int aad_len, unsigned char *input_buffer,
                             unsigned int input_len, unsigned char *shared_key, unsigned char *output_buffer,
                             bool op = true);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    unsigned int serializePublicKey(EVP_PKEY *key, unsigned char *buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    int digsignVerify(EVP_PKEY *peer_pubkey, unsigned char *input_buffer, unsigned int input_size,
                      unsigned char *output_buffer);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    int authDecrypt(unsigned char *input_buffer, unsigned int input_len, unsigned char *shared_key, short &message_type,
                    unsigned char *output_aad, unsigned int &aad_len, unsigned char *output_buffer, bool op = true);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    int establishSession(EVP_PKEY *user_key, unsigned char *sessionkey, unsigned char *signed_buffer,
                         unsigned int &buffer_size);

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    EVP_PKEY *dhGenerateKey();

    //------------------------------------------------------------------------------------------------------------------
    /**
     *
     **/
    EVP_PKEY *checkServerCertificate(unsigned char *buffer, long buffer_size);
};

#endif // CRYPTOGRAPHY_H