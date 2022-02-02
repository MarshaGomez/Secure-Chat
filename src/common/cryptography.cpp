#include "cryptography.h"
#include "utility.h"

// Here you can see all the component of our security module
// Kerchoff's Principle: the enemy knows the system but s8he doesn't knows the secret

const EVP_CIPHER *Cryptography::AE_cipher = EVP_aes_128_gcm();
int Cryptography::AE_iv_len = EVP_CIPHER_iv_length(AE_cipher);
int Cryptography::AE_block_size = EVP_CIPHER_block_size(AE_cipher);
const EVP_MD *Cryptography::md = EVP_sha256();
CryptoEVP *Cryptography::crypto_evp = (CryptoEVP *)malloc(sizeof(struct CryptoEVP));

Cryptography::Cryptography()
{
}

Cryptography::~Cryptography()
{
    free(crypto_evp);
}

// CERTIFICATES AND KEYS HANDLER FUNCTIONS

// Read a Private Key from file named username.pem protected by password and return the key (in the argument)
void Cryptography::readPrivateKey(const std::string username, const std::string password, EVP_PKEY *&privateKey)
{
    FILE *file;
    std::string path;
    path = DIR_PRIVATE_KEY + username + ".pem";
    file = fopen(path.c_str(), "r");
    if (!file)
        throw std::runtime_error("File doesn't exists in readPrivateKey().");
    privateKey = PEM_read_PrivateKey(file, NULL, NULL, (char *)password.c_str());
    if (!privateKey)
    {
        fclose(file);
        throw std::runtime_error("Private Key doesn't exists in readPrivateKey().");
    }

    fclose(file);
}

// Load Certificate from file and store it in a X509 Structure (argument)
void Cryptography::loadCertificate(X509 *&cert, const char *path)
{
    FILE *file = fopen(path, "r");
    if (!file)
        throw std::runtime_error("Error in loadCertificate(): File not found!");
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    if (!cert)
    {
        fclose(file);
        throw std::runtime_error("Error in loadCertificate(): Problem with the pem file!");
    }

    fclose(file);
}

// Load the Certificate Revocation List from file
void Cryptography::loadCRL(X509_CRL *&cert, const char *path)
{
    FILE *file = fopen(path, "r");

    if (!file)
        throw std::runtime_error("Error in loadCRL(): File not found!");

    cert = PEM_read_X509_CRL(file, NULL, NULL, NULL);
    if (!cert)
    {
        fclose(file);
        throw std::runtime_error("Error in loadCertificate(): CRL not found!");
    }

    fclose(file);
}

// Check if a certificate of the Server is validate by a CA and not revoked
EVP_PKEY *Cryptography::checkServerCertificate(unsigned char *buffer, long length)
{
    // Load the CA's certificate
    char *certificateCA = (char *)CA_CERTIFICATE;
    char *certificateCRL = (char *)CA_CRL;
    X509_STORE_CTX *cert_ctx;
    X509 *cert_ca, *cert;
    X509_CRL *cert_crl;
    X509_STORE *store;
    BIO *bio;

    loadCertificate(cert_ca, certificateCA);
    loadCRL(cert_crl, certificateCRL);
    cert_ctx = X509_STORE_CTX_new();
    store = X509_STORE_new();

    if (!store)
        throw std::runtime_error("Error in checkServerCertificate(): store is NULL!");
    try
    {
        if (X509_STORE_add_cert(store, cert_ca) != 1)
            throw std::runtime_error("Error in checkServerCertificate(): add cert in STORE_add_cert() !");

        if (X509_STORE_add_crl(store, cert_crl) != 1)
            throw std::runtime_error("Error in checkServerCertificate(): add cert in STORE_add_crl()");

        if (X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1)
            throw std::runtime_error("Error in checkServerCertificate(): add cert in STORE_set_flags()");
    }
    catch (const std::exception &e)
    {
        X509_STORE_free(store);
        throw std::runtime_error("Error in checkServerCertificate(): an exception occurred!");
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio)
        throw std::runtime_error("Error in checkServerCertificate(): bio is null");
    if (!BIO_write(bio, buffer, length))
        throw std::runtime_error("Error in checkServerCertificate(): writing in bio failed!");

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert)
        throw std::runtime_error("Error in checkServerCertificate():reading bio failed!");
    BIO_free(bio);

    // verify the certificate:
    cert_ctx = X509_STORE_CTX_new();
    if (!cert_ctx)
        throw std::runtime_error("Error in checkServerCertificate(): cert_ctx is null!");
    if (X509_STORE_CTX_init(cert_ctx, store, cert, NULL) != 1)
        throw std::runtime_error("Error in checkServerCertificate(): CTX_init failed!");
    if (X509_verify_cert(cert_ctx) != 1)
        throw std::runtime_error("Error in checkServerCertificate(): verify cert failed!");

    EVP_PKEY *server_pubkey;
    getPublicKey(cert, server_pubkey);

    X509_free(cert);
    X509_STORE_free(store);
    X509_STORE_CTX_free(cert_ctx);

    return server_pubkey;
}

// Deserialize public key passed in a buffer with the BIO Function
void Cryptography::deserializePublicKey(unsigned char *buffer, unsigned int length, EVP_PKEY *&key)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if (!bio)
        throw std::runtime_error("Error in deserializePublicKey(): BIO in null!");

    if (BIO_write(bio, buffer, length) <= 0)
        throw std::runtime_error("Error in deserializePublicKey(): BIOwrite() failed!");

    key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    if (!key)
    {
        BIO_free(bio);
        throw std::runtime_error("Error in deserializePublicKey(): key is null!");
    }

    BIO_free(bio);
}

// Read Public Key from a X509 Certificate file
void Cryptography::getPublicKey(X509 *cert, EVP_PKEY *&key)
{
    key = X509_get_pubkey(cert);
    if (!key)
        throw std::runtime_error("Error in getPublicKey()");
}

// FUNCTIONS FOR GENERATE SAFE VALUES (SECURE CODING STYLE )

// Random number generator ( Unpredictable Quantity )
void Cryptography::newNonce(unsigned char *nonce)
{
    if (RAND_poll() != 1)
        throw std::runtime_error("An error occurred in RAND_poll.");
    if (RAND_bytes((unsigned char *)&nonce[0], NONCE_SIZE) != 1)
        throw std::runtime_error("An error occurred in RAND_bytes.");
}

// Safe Increment Counter ( Secure Coding )
void Cryptography::safeIncrement(unsigned int &value)
{
    if (value == UINT_MAX)
        value = 0;
    else
        value++;
}

// EMPHERAL DH KEY GENERATION FUNCTIONS

// Generate DH Ephemeral Key with Standard Parameters (256bit Curve)
EVP_PKEY *Cryptography::dhGenerateKey()

{
    printf("I'm generating DH Ephemeral Key with Standard parameters (256-bit curve=128 bit security strength) \n");

    // Parameter context generation
    EVP_PKEY_CTX *PDHctx;
    if (NULL == (PDHctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)))
        printError();
    if (1 != (EVP_PKEY_paramgen_init(PDHctx)))
        printError();
    if (1 != (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(PDHctx, NID_X9_62_prime256v1)))
        printError();

    // Parameters Generation
    EVP_PKEY *params = NULL;
    if (!EVP_PKEY_paramgen(PDHctx, &params))
        printError();
    EVP_PKEY_CTX_free(PDHctx);

    // Ephemeral Key Context Generation
    EVP_PKEY_CTX *DHctx;
    if (NULL == (DHctx = EVP_PKEY_CTX_new(params, NULL)))
        printError();

    // Generate the key
    EVP_PKEY *myEphemeralKey = NULL;
    if (1 != EVP_PKEY_keygen_init(DHctx))
        printError();
    if (1 != EVP_PKEY_keygen(DHctx, &myEphemeralKey))
        printError();
    EVP_PKEY_CTX_free(DHctx);

    printf("The DH Ephemeral Key is ready! \n");
    /* Write into a buffer*/
    return myEphemeralKey;
}

// Derive the shared secret using the Public Key of the peer
void Cryptography::secretDerivation(EVP_PKEY *key, EVP_PKEY *peerPubKey, unsigned char *buffer)
{
    EVP_PKEY_CTX *pubKeyCTX;
    size_t secretLength;
    unsigned char *secret;

    if (!peerPubKey)
        throw std::runtime_error("Error in secretDerivation(): peerPubKey is null!");

    pubKeyCTX = EVP_PKEY_CTX_new(key, NULL);
    if (!pubKeyCTX)
        throw std::runtime_error("Error in secretDerivation(): CTX is null!");

    if (EVP_PKEY_derive_init(pubKeyCTX) < 1)
    {
        EVP_PKEY_CTX_free(pubKeyCTX);
        throw std::runtime_error("Error in secretDerivation(): problem with derive_init()");
    }

    if (EVP_PKEY_derive_set_peer(pubKeyCTX, peerPubKey) < 1)
    {
        EVP_PKEY_CTX_free(pubKeyCTX);
        throw std::runtime_error("Error in secretDerivation(): problem with derive_set_peer()");
    }

    if (EVP_PKEY_derive(pubKeyCTX, NULL, &secretLength) < 1)
    {
        EVP_PKEY_CTX_free(pubKeyCTX);
        throw std::runtime_error("Error in secretDerivation(): problem with derive() to get secretLength");
    }

    secret = (unsigned char *)malloc(secretLength);
    if (!secret)
    {
        EVP_PKEY_CTX_free(pubKeyCTX);
        throw std::runtime_error("Error in secretDerivation(): problem with secret allocation");
    }

    if (EVP_PKEY_derive(pubKeyCTX, secret, &secretLength) < 1)
    {
        EVP_PKEY_CTX_free(pubKeyCTX);
        OPENSSL_free(secret);
        throw std::runtime_error("Error in secretDerivation(): problem with derive_set_peer()");
    }

    EVP_PKEY_CTX_free(pubKeyCTX);
    dhGenerateSessionKey(secret, (unsigned int)secretLength, buffer);
    OPENSSL_free(secret);
}

// Generate Session Key from the shared secret by hashing it (it is more secure)
unsigned int Cryptography::dhGenerateSessionKey(unsigned char *shared_secret, unsigned int shared_secretlen,
                                                unsigned char *sessionkey)
{
    unsigned int sessionkey_len;
    int ret;
    EVP_MD_CTX *hctx;

    /* Context allocation */
    hctx = EVP_MD_CTX_new();
    if (!hctx)
    {
        std::cerr << "Error in dhGenerateSessionKey(): EVP_MD_CTX_new()";
        exit(1);
    }
    /* Hashing (initialization + single update + finalization */
    ret = EVP_DigestInit(hctx, md);
    if (ret != 1)
    {
        std::cerr << "Error in dhGenerateSessionKey(): EVP_DigestInit()";
        ;
        exit(1);
    }
    ret = EVP_DigestUpdate(hctx, shared_secret, shared_secretlen);
    if (ret != 1)
    {
        std::cerr << "Error in dhGenerateSessionKey(): EVP_DigestUpdate()";
        ;
        exit(1);
    }
    ret = EVP_DigestFinal(hctx, sessionkey, &sessionkey_len);
    if (ret != 1)
    {
        std::cerr << "Error in dhGenerateSessionKey(): EVP_DigestFinal()";
        ;
        exit(1);
    }
    /* Context deallocation */
    EVP_MD_CTX_free(hctx);
    return sessionkey_len;
}

// DIGITAL SIGNATURE FUNCTIONS

// Digital Signature Sign Operation
unsigned int Cryptography::digsignSign(EVP_PKEY *prvkey, unsigned char *clear_buf, unsigned int clear_size,
                                       unsigned char *output_buffer)
{
    int ret; // store the return of the function to check errors
    if (clear_size > MAX_SIZE)
    {
        std::cerr << "Error in digsignSign(): message too big(invalid)\n";
        exit(1);
    }
    // create the signature context:
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        std::cerr << "Error in digsignSign(): EVP_MD_CTX_new()\n";
        exit(1);
    }
    ret = EVP_SignInit(md_ctx, md);
    if (ret == 0)
    {
        std::cerr << "Error in digsignSign(): EVP_SignInit() \n";
        exit(1);
    }
    ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
    if (ret == 0)
    {
        std::cerr << "Error in digsignSign(): EVP_SignUpdate() \n";
        exit(1);
    }
    unsigned int sgnt_size;
    unsigned char *signature_buffer = allocateValue(signature_buffer, EVP_PKEY_size(prvkey));

    ret = EVP_SignFinal(md_ctx, signature_buffer, &sgnt_size, prvkey);
    if (ret == 0)
    {
        std::cerr << "Error in digsignSign(): EVP_SignFinal() \n";
        exit(1);
    }

    unsigned int written = 0;
    // Write the signature size (convert to char since it is a char buffer)
    memcpy(output_buffer, (unsigned char *)&sgnt_size, sizeof(unsigned int));
    written += sizeof(unsigned int);
    // Write the signature
    memcpy(output_buffer + written, signature_buffer, sgnt_size);
    written += sgnt_size;
    // Write the signed content
    memcpy(output_buffer + written, clear_buf, clear_size);
    written += clear_size;
    EVP_MD_CTX_free(md_ctx);
    return written;
}

// Digital Signature Verify
int Cryptography::digsignVerify(EVP_PKEY *peer_pubkey, unsigned char *input_buffer, unsigned int input_size,
                                unsigned char *output_buffer)
{

    // Get the signature size from the buffer and convert it to int (see digsignSign function)
    unsigned int sgnt_size = *(unsigned int *)input_buffer;
    unsigned int read = sizeof(unsigned int);
    if (input_size <= sizeof(unsigned int) + sgnt_size)
    {
        std::cerr << "Error in digsignVerify(): problem in reading signature size! \n";
        exit(1);
    }

    // Get the signature from the buffer
    unsigned char *signature_buffer = allocateValue(signature_buffer, sgnt_size);
    memcpy(signature_buffer, input_buffer + read, sgnt_size);
    read += sgnt_size;

    // Get the clear content
    memcpy(output_buffer, input_buffer + read, input_size - read);

    // Signature Context
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        std::cerr << "Error in digsignVerify(): EVP_MD_CTX is null!\n";
        exit(1);
    }

    int ret; // store the return of the functions to check errors

    // Verify Init
    ret = EVP_VerifyInit(md_ctx, md);
    if (ret == 0)
    {
        std::cerr << "Error in digsignVerify(): EVP_VerifyInit \n";
        exit(1);
    }
    ret = EVP_VerifyUpdate(md_ctx, input_buffer + read, input_size - read);
    if (ret == 0)
    {
        std::cerr << "Error in digsignVerify(): EVP_VerifyUpdate \n";
        exit(1);
    }

    // Verify the signature with the peer public key
    ret = EVP_VerifyFinal(md_ctx, signature_buffer, sgnt_size, peer_pubkey);
    if (ret == -1)
    { // it is 0 if invalid signature, -1 if some other error, 1 if success.
        std::cerr << "Error in digsignVerify(): EVP_VerifyFinal returned an error with the Signature! \n";
        ERR_error_string_n(ERR_get_error(), (char *)output_buffer, MAX_SIZE);
        std::cerr << output_buffer << "\n";
        exit(1);
    }
    else if (ret == 0)
    {
        std::cerr << "Error: Invalid signature!\n";
        return -1; // handle it in client and server!
    }

    // Free the context
    EVP_MD_CTX_free(md_ctx);

    return input_size - read;
}

// AUTHENTICATED ENCRYPTION AND DECRYPTION FUNCTIONS WITH AES-GCM-128

// Authenticated Encryption of a chat message (message type controls included)
unsigned int Cryptography::authEncrypt(short message_type, unsigned char *aad, unsigned int aad_len, unsigned char *input_buffer,
                                       unsigned int input_len, unsigned char *shared_key, unsigned char *output_buffer, bool op)
{

    // Check for the size
    if (input_len > MAX_SIZE || aad_len > MAX_SIZE)
    {
        std::cerr << "Error in authEncrypt(): AAD or PT too big";
        return -1;
    }

    // Check if message_type is present and compute dimensions accordingly
    unsigned int opsize = 0;
    if (op)
        opsize = sizeof(short);
    if (input_len + aad_len > MAX_SIZE - AE_block_size - sizeof(unsigned int) - AE_iv_len - AE_TAG_LEN - opsize)
    {
        std::cerr << "Error in authEncrypt(): Packet is too big";
        return -1;
    }

    // Generate random IV
    int ret;
    unsigned char *iv = allocateValue(iv, AE_iv_len);
    RAND_poll();
    ret = RAND_bytes((unsigned char *)&iv[0], AE_iv_len);
    if (ret != 1)
    {
        std::cerr << "Error in authEncrypt(): RAND_bytes()";
        exit(1);
    }

    // Encryption Context and Operations
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ciphertext_len = 0;

    unsigned char *ciphertext = allocateValue(ciphertext, input_len + AE_block_size);
    unsigned char *tag = allocateValue(tag, AE_TAG_LEN);
    unsigned char *complete_aad = allocateValue(complete_aad, sizeof(short) + aad_len);

    // if message_type is present add on the AAD
    if (op)
        memcpy(complete_aad, &message_type, opsize);

    // Copy the residual aad into the header
    memcpy(complete_aad + opsize, aad, aad_len);

    if (!(ctx = EVP_CIPHER_CTX_new()))
        printError();
    if (1 != EVP_EncryptInit(ctx, AE_cipher, shared_key, iv))
        printError();

    // Update the CONTEXT with the AAD (it doesn't populate the ciphertext)
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, complete_aad, aad_len + opsize))
        printError();

    // Update the context with the Plain Text
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, input_buffer, input_len))
        printError();
    ciphertext_len = len;

    // Encrypt Final
    if (1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len))
        printError();
    ciphertext_len += len;

    // Getting the tag (authentication) from the context
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AE_TAG_LEN, tag))
        printError();

    unsigned int output_len = AE_TAG_LEN + ciphertext_len + AE_iv_len + aad_len + sizeof(unsigned int) + opsize;
    unsigned int written = 0;

    // Copy all the values in the output buffer

    // If there is the message_type copy it
    if (op)
        memcpy(output_buffer, (unsigned char *)&message_type, opsize);
    written += opsize;

    memcpy(output_buffer + written, tag, AE_TAG_LEN);
    written += AE_TAG_LEN;
    memcpy(output_buffer + written, iv, AE_iv_len);
    written += AE_iv_len;
    memcpy(output_buffer + written, (unsigned char *)&aad_len, sizeof(unsigned int));
    written += sizeof(unsigned int);
    memcpy(output_buffer + written, aad, aad_len);
    written += aad_len;
    memcpy(output_buffer + written, ciphertext, ciphertext_len);
    written += ciphertext_len;

    // Clean all the dinamic values (remove secret values in the memory)
    EVP_CIPHER_CTX_free(ctx);
    free(tag);
    free(iv);
    free(ciphertext);
    return written;
}

// Authenticated Decryption
int Cryptography::authDecrypt(unsigned char *input_buffer, unsigned int input_len, unsigned char *shared_key, short &message_type,
                              unsigned char *output_aad, unsigned int &aad_len, unsigned char *output_buffer, bool op)
{
    unsigned int opsize = 0;
    // If there is  message_type manage it
    if (op)
        opsize = sizeof(short);

    // Check for consistency of the message received
    if (input_len <= AE_iv_len + AE_TAG_LEN + opsize)
    {
        std::cerr << "Error in authDecrypt(): Message size is not consistend with the input size expected! \n";
        return -1;
    }
    if (input_len > MAX_SIZE)
    {
        std::cerr << "Error in authDecrypt(): Input is over the MAX_SIZE allowed! \n";
        return -1;
    }

    // Create the context for the decryption
    EVP_CIPHER_CTX *ctx;
    unsigned int read = 0;

    // If there is message_type manage it and read it from the buffer (convert to short)
    if (op)
        message_type = *(short *)(input_buffer);
    read += opsize;

    // Allocate variables for decryption
    unsigned char *iv = allocateValue(iv, AE_iv_len);
    unsigned char *tag = allocateValue(tag, AE_TAG_LEN);

    // Read the tag
    memcpy(tag, input_buffer + read, AE_TAG_LEN);
    read += AE_TAG_LEN;

    // Read the IV
    memcpy(iv, input_buffer + read, AE_iv_len);
    read += AE_iv_len;

    // Read the AAD LEN and check the consistency
    aad_len = *(unsigned int *)(input_buffer + read);
    read += sizeof(unsigned int);
    if (input_len < read + aad_len)
    {
        std::cerr << "Error in authDecrypt(): AAD Length is not consistent! \n";
        return -1;
    }
    if (aad_len > MAX_SIZE)
    {
        std::cerr << "Error in authDecrypt(): AAD Length is greater than the MAX_SIZE! \n";
        return -1;
    }
    // If AAD is consistent copy into the output AAD (argument of function)
    memcpy(output_aad, input_buffer + read, aad_len);
    read += aad_len;

    // Copy the entire AAD ( message_type + other message fields ) into a variable complete_aad
    unsigned char *complete_aad = allocateValue(complete_aad, opsize + aad_len);
    if (op)
        memcpy(complete_aad, &message_type, opsize);    // first the message_type
    memcpy(complete_aad + opsize, output_aad, aad_len); // last the residual fields

    /*
        Remember that the message packet has the form:
        | message_type | other authenticated fields | encrypted message |
    */

    // Copy the ciphertect
    unsigned int ciphertext_len = input_len - read;
    if (ciphertext_len > MAX_SIZE)
    {
        std::cerr << "Error in authDecrypt(): Ciphertext Length is greater than the MAX_SIZE!";
        return -1;
    }
    unsigned char *ciphertext = allocateValue(ciphertext, ciphertext_len);
    memcpy(ciphertext, input_buffer + read, ciphertext_len);

    // Decrypt the message
    int ret;
    int len;
    unsigned int output_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        printError();
    if (!EVP_DecryptInit(ctx, AE_cipher, shared_key, iv))
        printError();

    // Update the CONTEXT with the AAD (it doesn't populate the ciphertext)
    if (!EVP_DecryptUpdate(ctx, NULL, &len, complete_aad, opsize + aad_len))
        printError();
    // Update the context with the Cipher Text
    if (!EVP_DecryptUpdate(ctx, output_buffer, &len, ciphertext, ciphertext_len))
        printError();
    output_len = len;

    // Update the context with the TAG we expect (received from the other part)
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AE_TAG_LEN, tag))
        printError();

    // Finalize the CTX
    ret = EVP_DecryptFinal(ctx, output_buffer + output_len, &len);

    // Free the variables
    EVP_CIPHER_CTX_cleanup(ctx);
    free(tag);
    free(iv);
    free(ciphertext);

    // Check for the results
    if (ret > 0)
    {
        // On success (TAG OK)
        output_len += len;
        return output_len;
    }
    else
    {
        // On failure (TAG MISMATCH)
        std::cerr << "auth decrypt: Verification failed!";
        return -1;
    }
}

// Serialize the public key from a PKEY structure and write into a buffer with BIO
unsigned int Cryptography::serializePublicKey(EVP_PKEY *key, unsigned char *buffer)
{
    BIO *bio;
    unsigned char *bufferSerialized;
    long length;

    bio = BIO_new(BIO_s_mem());
    if (!bio)
        throw std::runtime_error("Error in serializePublicKey(): BIO is null! ");

    if (PEM_write_bio_PUBKEY(bio, key) != 1)
    {
        BIO_free(bio);
        throw std::runtime_error("Error in serializePublicKey(): PEM_BIO_write_bio_PUBKEY() failed!");
    }

    length = BIO_get_mem_data(bio, &bufferSerialized);
    memcpy(buffer, bufferSerialized, length);

    if (length < 0 || length > UINT_MAX)
    {
        BIO_free(bio);
        throw std::runtime_error("Error in serializePublicKey(): Some problems with the reading of the Public Key!");
    }

    BIO_free(bio);

    return length;
}

// Print Error and exit fuction
void Cryptography::printError(void)
{
    ERR_print_errors_fp(stderr);
    exit(1);
}

/**----------------------  IN THIS PART OF THE CODE THERE ARE THE CRYPTO UTILITIES FOR THE CLIENT --------------------------- **/

// Manage accept message in the client
void Cryptography::onAccept(unsigned char *buffer, unsigned char *message, unsigned char *aad, unsigned int aadLength)
{
    int ret;
    int message_size;
    EVP_PKEY *peer_key;

    *crypto_evp->message_type = REQUEST_ACCEPTED;

    unsigned char *mynonce = newNonce();

    memcpy(buffer, crypto_evp->storedNonce, NONCE_SIZE);
    memcpy(buffer + NONCE_SIZE, mynonce, NONCE_SIZE);

    // Create the ECDH Publick Key
    EVP_PKEY *mydhkey = dhGenerateKey();

    long keysize = serializePublicKey(mydhkey, buffer + (2 * NONCE_SIZE));

    message_size = digsignSign(crypto_evp->user_key, buffer, NONCE_SIZE + NONCE_SIZE + keysize, message);

    memcpy(aad, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int));
    memcpy(aad + sizeof(unsigned int), message, message_size);

    ret = authEncrypt(REQUEST_ACCEPTED, aad, message_size + sizeof(unsigned int),
                      (unsigned char *)crypto_evp->peer, strlen(crypto_evp->peer) + 1,
                      crypto_evp->cs_session_key, buffer);
    sendMessage(crypto_evp->sockfd, ret, buffer);
    safeIncrement(*crypto_evp->server_send);

    message_size = receiveMessage(crypto_evp->sockfd, buffer);
    if (message_size > 0)
    {
        unsigned int received_counter = *(unsigned int *)(buffer + MSGHEADER);
        if (received_counter == *crypto_evp->server_receive)
        {
            ret = authDecrypt(buffer, message_size, crypto_evp->cs_session_key, *crypto_evp->message_type, aad, aadLength,
                              message);
            if (ret >= 0 && *crypto_evp->message_type == CHAT_SESSION)
            {
                safeIncrement(*crypto_evp->server_receive);
                unsigned int pubkey_size = aadLength - sizeof(unsigned int);
                deserializePublicKey(aad + sizeof(unsigned int), pubkey_size, peer_key);
            }
        }
    }
    // Wait the other ECDH Public Key (Message 6)
    message_size = receiveMessage(crypto_evp->sockfd, buffer);
    if (message_size > 0)
    {
        unsigned int received_counter = *(unsigned int *)(buffer + MSGHEADER);
        if (received_counter == *crypto_evp->server_receive)
        {
            ret = authDecrypt(buffer, message_size, crypto_evp->cs_session_key, *crypto_evp->message_type, aad, aadLength,
                              message);
            if (ret >= 0 && *crypto_evp->message_type == CHAT_SESSION)
            {
                safeIncrement(*crypto_evp->server_receive);
                unsigned int s_size = *(unsigned int *)(aad + sizeof(unsigned int));
                s_size += (2 * sizeof(unsigned int));
                // Check the Nonce for the freshness
                if (memcmp(aad + s_size, mynonce, NONCE_SIZE) != 0)
                {
                    std::cerr << "Nonce received is not valid!";
                    exit(1);
                }
                free(mynonce);

                message_size = digsignVerify(peer_key, aad + sizeof(unsigned int),
                                             aadLength - sizeof(unsigned int), buffer);
                if (message_size <= 0)
                {
                    std::cerr << "signature is invalid";
                    exit(1);
                }
                free(peer_key);

                // Extract the Peer's Public Key
                EVP_PKEY *ecdh_peer_pubkey;
                deserializePublicKey(buffer + NONCE_SIZE, message_size - NONCE_SIZE, ecdh_peer_pubkey);

                // Compute the shared secret
                secretDerivation(mydhkey, ecdh_peer_pubkey, crypto_evp->cc_session_key);

                EVP_PKEY_free(ecdh_peer_pubkey);
                EVP_PKEY_free(mydhkey);
            }
        }
    }
    *crypto_evp->client_receive = 0;
    *crypto_evp->client_send = 0;
}

// Manage refuse message in the client
void Cryptography::onRefuse(unsigned char *buffer)
{
    int ret;
    *crypto_evp->message_type = REQUEST_REFUSED;
    ret = authEncrypt(*crypto_evp->message_type, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int),
                      (unsigned char *)crypto_evp->peer, strlen(crypto_evp->peer) + 1,
                      crypto_evp->cs_session_key, buffer);
    sendMessage(crypto_evp->sockfd, ret, buffer);
    safeIncrement(*crypto_evp->server_send);
}

// Manage exit message in the client
void Cryptography::onExit(std::string username, unsigned char *buffer)
{
    int ret;
    *crypto_evp->message_type = EXITED;

    ret = authEncrypt(*crypto_evp->message_type, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int),
                      (unsigned char *)username.c_str(), username.length() , crypto_evp->cs_session_key,
                      buffer);
    sendMessage(crypto_evp->sockfd, ret, buffer);
    safeIncrement(*crypto_evp->server_send);

    *crypto_evp->done = true;
}

// Manage user list message in the client
void Cryptography::onUserList(std::string username, unsigned char *buffer)
{
    int ret;
    *crypto_evp->message_type = ONLINE_USERS;

    ret = authEncrypt(*crypto_evp->message_type, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int),
                      (unsigned char *)username.c_str(), username.length() , crypto_evp->cs_session_key,
                      buffer);
    sendMessage(crypto_evp->sockfd, ret, buffer);
    safeIncrement(*crypto_evp->server_send);
}

// Manage startchat message in the client
void Cryptography::onStartChat(std::string command, unsigned char *buffer, unsigned char *aad)
{
    int ret;
    std::string peer = command.substr(11, command.length());
    if (peer.length() > USERNAME_LENGTH)
        std::cerr << "Invalid username." << std::endl;
    else
    {
        *crypto_evp->message_type = REQUEST_TO_TALK;
        // send  RTT
        *crypto_evp->waiting = true;
        unsigned char *peer_name = allocateValue(peer_name, peer.length());

        peer.copy((char *)peer_name, peer.length());
        peer.copy(crypto_evp->peer, peer.length());
        crypto_evp->peer[peer.length()] = '\0';

        newNonce(crypto_evp->storedNonce);

        memcpy(aad, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int));
        memcpy(aad + sizeof(unsigned int), crypto_evp->storedNonce, NONCE_SIZE);
        ret = authEncrypt(*crypto_evp->message_type, aad, sizeof(unsigned int) + NONCE_SIZE,
                          (unsigned char *)crypto_evp->peer, strlen(crypto_evp->peer), crypto_evp->cs_session_key, buffer);
        sendMessage(crypto_evp->sockfd, ret, buffer);
        safeIncrement(*crypto_evp->server_send);
        std::cout << "REQUEST TO TALK SENT TO: " << peer << std::endl;
    }
}

// Manage chat message in the client
void Cryptography::onChatting(std::string command, unsigned char *buffer, unsigned char *aad, unsigned char *message)
{
    int ret, message_size;

    if (command.length() > MAX_SIZE)
        std::cerr << "message too long." << std::endl;
    else if (command.length() > 0)
    {
        *crypto_evp->message_type = TEXT_MESSAGE;
        if (command.compare("!exit") == 0)
        {
            *crypto_evp->message_type = CHAT_CLOSED;
            *crypto_evp->chatting = false;
            *crypto_evp->waiting = false;
            *crypto_evp->pending = false;
        }
        command.copy((char *)aad, command.length());
        aad[command.length()] = '\0';
        // encrypt the message for the peer
        message_size = authEncrypt(TEXT_MESSAGE, (unsigned char *)crypto_evp->client_send, sizeof(unsigned int), aad,
                                   command.length(), crypto_evp->cc_session_key, message, false);
        memcpy(aad, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int));
        memcpy(aad + sizeof(unsigned int), message, message_size);
        // encrypt everything for the server
        // note that if message_type=8 the server will only send to the peer
        // the message to inform that its peer is exited
        ret = authEncrypt(*crypto_evp->message_type, aad, message_size + sizeof(unsigned int),
                          (unsigned char *)crypto_evp->peer, strlen(crypto_evp->peer) + 1, crypto_evp->cs_session_key,
                          buffer);
        sendMessage(crypto_evp->sockfd, ret, buffer);
        safeIncrement(*crypto_evp->server_send);
        safeIncrement(*crypto_evp->client_send);
    }
}

// Manage accept message in the client
void Cryptography::acceptMessage(int ret, unsigned char *buffer, unsigned char *message, unsigned char *aad, unsigned int aadLength)
{
    long pubkey_size = *(long *)(aad + sizeof(unsigned int));
    if (*crypto_evp->waiting &&
        memcmp(crypto_evp->storedNonce, aad + sizeof(long) + pubkey_size + 256 + 2 * (sizeof(unsigned int)),
               NONCE_SIZE) == 0 &&
        memcmp(message, crypto_evp->peer, ret - 1) == 0)
    {
        ret = establishSession(crypto_evp->user_key, crypto_evp->cc_session_key, aad, aadLength);
        if (ret >= 0)
        {
            memcpy(buffer, (unsigned char *)crypto_evp->server_send, sizeof(unsigned int));
            memcpy(buffer + sizeof(unsigned int), aad, aadLength);
            ret = authEncrypt(CHAT_SESSION, buffer, aadLength + sizeof(unsigned int),
                              (unsigned char *)crypto_evp->peer,
                              strlen(crypto_evp->peer) + 1, crypto_evp->cs_session_key, aad);
            if (ret >= 0)
            {
                sendMessage(crypto_evp->sockfd, ret, aad);
                safeIncrement(*crypto_evp->server_send);
                *crypto_evp->waiting = false;
                *crypto_evp->chatting = true;
                *crypto_evp->client_receive = 0;
                *crypto_evp->client_send = 0;
            }
        }
    }
}

// Manage refuse message in the client
void Cryptography::refuseMessage(int ret, unsigned char *message)
{
    if (*crypto_evp->waiting && memcmp(message, crypto_evp->peer, ret - 1) == 0)
    {
        *crypto_evp->waiting = false;
        std::cout << "\n--------------------------------------------------" << std::endl;
        std::cout << crypto_evp->peer << " refused chat." << std::endl;
        std::cout << "Press enter to continue ..." << std::endl;
    }
}

// Manage chat message in the client
void Cryptography::chatMessage(int ret, std::string username, unsigned char *buffer, unsigned char *message, unsigned int msgLength, unsigned char *aad, unsigned int aadLength)
{
    if (*crypto_evp->chatting)
    {
        char user[USERNAME_LENGTH + 1];
        memcpy(user, message, USERNAME_LENGTH + 1);
        unsigned int cntr = *(unsigned int *)(aad + MSGHEADER - sizeof(short) +
                                              sizeof(unsigned int));
        if (cntr == *crypto_evp->client_receive)
        {
            unsigned int msgsize;
            memset(message, 0, msgLength);
            ret = authDecrypt(aad + sizeof(unsigned int), aadLength - sizeof(unsigned int),
                              crypto_evp->cc_session_key, *crypto_evp->message_type, buffer, msgsize, message,
                              false);

            if (ret > 0 && ret < MAX_SIZE)
            {
                safeIncrement(*crypto_evp->client_receive);
                std::cout << "\r" << capitalize(user) << ": " << message << std::endl;
                std::cout << capitalize(username) << ": ";
                fflush(stdout);
            }
        }
    }
}

// Manage request message in the client
void Cryptography::requestMessage(int ret, unsigned char *message, unsigned char *aad)
{
    if (ret > 0 && ret <= USERNAME_LENGTH+1) 
    {
        *crypto_evp->pending = true;
        memcpy(crypto_evp->peer, message, ret);
        memcpy(crypto_evp->storedNonce, aad + sizeof(unsigned int), NONCE_SIZE);
        showNewRequestMenu();
    }
}

// Manage refuse message in the client
void Cryptography::showNewRequestMenu()
{
    std::cout << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "\033[34m"
              << "Look, " << crypto_evp->peer << " is trying to contact you." << std::endl;
    std::cout << "If you want to start the secret chat type !accept or if you want to ignore this request type !refuse.";
    std::cout << "\033[0m" << std::endl;
}

// Manage refuse message in the client
void Cryptography::closeChat(int ret, unsigned char *message)
{
    if (memcmp(message, crypto_evp->peer, ret - 1) == 0)
    {
        *crypto_evp->pending = false;
        *crypto_evp->chatting = false;
        *crypto_evp->waiting = false;
        std::cout << "\n--------------------------------------------------" << std::endl;
        std::cout << crypto_evp->peer << " leaves the chat :( " << std::endl;
        std::cout << "Press enter to continue ..." << std::endl;
    }
}

// Manage user not found message in the client
void Cryptography::userNotFound()
{
    std::cout << "User not found." << std::endl;

    *crypto_evp->waiting = false;
}

// Manage userlist message in the client
void Cryptography::getUserList(unsigned char *buffer)
{
    unsigned int count = 0;
    char username[USERNAME_LENGTH + 1];
    std::cout << "\33[2K";

    // tokenize received string
    const char delimiter[3] = ", ";
    char *token;

    token = strtok((char *)buffer, delimiter);

    if (token == NULL)
    {
        std::cout << "Sorry, no user online  " << std::endl;
    }
    else
    {
        std::cout << "\nFor start a conversation with one of the available users you can type the command !startchat <USERNAME> " << std::endl;
        std::cout << "\n   ONLINE USERS " << std::endl;
        std::cout << "   ------------" << std::endl;

        /* walk through other tokens */
        while (token != NULL)
        {
            std::cout << "   " << token << std::endl;

            token = strtok(NULL, delimiter);
        }
        std::cout << std::endl;
    }
}

// Generate a new nonce
unsigned char *Cryptography::newNonce()
{
    unsigned char *nonce = allocateValue(nonce, NONCE_SIZE);
    newNonce(nonce);

    return nonce;
}

// Send a Message with Secure Coding Check
void Cryptography::sendMessage(int sockfd, unsigned int msgLength, unsigned char *message)
{
    if (msgLength > MAX_SIZE)
        throw std::runtime_error("Message in sendMessage() is too large!");
    uint32_t length = htonl(msgLength);

    if (send(sockfd, &length, sizeof(uint32_t), 0) < 0)
        throw std::runtime_error("Error in sendMessage() while send()! Message is too large!");

    if (send(sockfd, message, msgLength, 0) <= 0)
        throw std::runtime_error("Error in sendMessage() while send() the message!");
}

// Get the Server DH Ephemeral Key in the message about the authentication Client-Server
// (Directly linked with the implementation of the Client and the server)
void Cryptography::getServerEphemeralKey(EVP_PKEY *&peerKey, EVP_PKEY *ecdhPrivateKey, unsigned char *&message, unsigned int &msgLength)
{
    unsigned char *nonce = allocateValue(nonce, NONCE_SIZE);

    memcpy(nonce, message + NONCE_SIZE, NONCE_SIZE);

    deserializePublicKey(message + NONCE_SIZE + NONCE_SIZE, msgLength - NONCE_SIZE - NONCE_SIZE, peerKey);

    msgLength = 0;
    memcpy(message, nonce, NONCE_SIZE);
    msgLength += NONCE_SIZE;
    unsigned int keysize = serializePublicKey(ecdhPrivateKey, message + msgLength);
    msgLength += keysize;
    free(nonce);
}

// Manage the message received in the socket and check sizes (both client and server)
unsigned int Cryptography::receiveMessage(int sockfd, unsigned char *message)
{
    int ret;
    uint32_t networknumber;

    unsigned int received = 0;

    ret = recv(sockfd, &networknumber, sizeof(uint32_t), 0);
    if (ret < 0)
    {
        std::cerr << " " << strerror(errno);
        exit(1);
    }
    if (ret > 0)
    {
        unsigned int msg_size = ntohl(networknumber);
        if (msg_size > MAX_SIZE)
        {
            std::cerr << "receive: message too big";
            return 0;
        }
        while (received < msg_size)
        {
            ret = recv(sockfd, message + received, msg_size - received, 0);
            if (ret < 0)
            {
                std::cerr << "message receive error";
                exit(1);
            }
            received += ret;
        }
        return msg_size;
    }
    return 0;
}

// Establish Session
int Cryptography::establishSession(EVP_PKEY *user_key, unsigned char *sessionkey, unsigned char *signed_buffer,
                                   unsigned int &length)
{
    int ret;

    long pubkey_size = *(long *)(signed_buffer + sizeof(unsigned int));

    EVP_PKEY *peerpubkey;
    deserializePublicKey(signed_buffer + sizeof(unsigned int) + sizeof(long), pubkey_size, peerpubkey);

    unsigned int signedsize = length - pubkey_size - sizeof(long) - sizeof(unsigned int);
    unsigned char *message = allocateValue(message, MAX_SIZE);

    unsigned char *temp = allocateValue(temp, signedsize);

    memcpy(temp, signed_buffer + sizeof(long) + pubkey_size + sizeof(unsigned int), signedsize);
    unsigned int message_size = digsignVerify(peerpubkey, temp, signedsize, message);
    if (message_size <= 0)
    {
        std::cerr << "signature is invalid";
        return -1;
    }
    EVP_PKEY *ecdh_peer_pubkey;

    EVP_PKEY *ecdh_priv_key = dhGenerateKey();

    getServerEphemeralKey(ecdh_peer_pubkey, ecdh_priv_key, message, message_size);
    length = digsignSign(user_key, message, message_size, signed_buffer);

    size_t slen;
    EVP_PKEY_CTX *derive_ctx;
    derive_ctx = EVP_PKEY_CTX_new(ecdh_priv_key, NULL);
    if (!derive_ctx)
        printError();
    if (EVP_PKEY_derive_init(derive_ctx) <= 0)
        printError();
    /*Setting the peer with its pubkey*/
    if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_peer_pubkey) <= 0)
        printError();
    /* Determine buffer length, by performing a derivation but writing the result nowhere */
    EVP_PKEY_derive(derive_ctx, NULL, &slen);
    unsigned char *shared_secret = allocateValue(shared_secret, slen);

    /*Perform again the derivation and store it in shared_secret buffer*/
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &slen) <= 0)
    {
        std::cerr << "ERR";
        exit(1);
    }
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(ecdh_peer_pubkey);
    EVP_PKEY_free(ecdh_priv_key);
    ret = dhGenerateSessionKey(shared_secret, (unsigned int)slen, sessionkey);
    free(shared_secret);
    return 0;
}
