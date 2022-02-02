// network parameters
#define PORT 8080
#define LOCALHOST "127.0.0.1"

// numeric parameters
#define KILO 1024

// message exchange parameters
#define MSG_HEADER_LENGTH 34

// server
#define MAX_CLIENTS 1000
#define USERNAME_LENGTH 20

// message types
#define EXITED 0
#define ONLINE_USERS 1
#define REQUEST_TO_TALK 2
#define REQUEST_ACCEPTED 3
#define REQUEST_REFUSED 4
#define TEXT_MESSAGE 5
#define CHAT_SESSION 6
#define UNKNOWN_USER 7
#define CHAT_CLOSED 8


// cryptography
#define PASSWORD_SIZE 20
#define MAX_SIZE 20*KILO
#define NONCE_SIZE 4
#define MSGHEADER 34
#define NONCE_LENGTH 4
#define AE_TAG_LEN 16


#define DIR_CA "../resources/security/CA/"
#define DIR_PUBLIC_KEY "../resources/security/Public_key/"
#define DIR_PRIVATE_KEY "../resources/security/Private_key/"

#define SERVER_CERTIFICATE "../resources/security/CA/server_cert.pem"
#define SERVER_PRV_KEY "../resources/security/Private_key/server.pem"
#define CA_CERTIFICATE "../resources/security/CA/ECORP_cert.pem"
#define CA_CRL "../resources/security/CA/ECORP_crl.pem"
