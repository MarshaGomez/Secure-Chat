#include "network.h"

Network::Network()
{
}

Network::Network(const int port, char *host, const int socketType)
{
    this->port = port;
    this->host = host;
    this->socketType = socketType;
}

Network::~Network() {}

void Network::setPort(const int port)
{
    this->port = port;
}

void Network::setHost(char *host)
{
    this->host = host;
}

void Network::newConnection()
{
    bzero((char *)&address, sizeof(address));
    this->sockfd = socket(AF_INET, socketType, 0);

    if ((this->sockfd) == -1)
        throw std::runtime_error("Socket creation error.");

    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    // inet_pton(): (1) on success |  (0) (-1) not contain a valid address
    if (inet_pton(AF_INET, host, &address.sin_addr) <= 0)
        throw std::runtime_error("Invalid address. Address not supported.");
}

void Network::startConnection()
{
    // fcntl(): (file status flags) on success | (-1) on error
    int flagsfd = fcntl(sockfd, F_GETFL, 0);

    // connect(): (0) on success | (-1) on error
    int connection = connect(sockfd, (struct sockaddr *)&address, sizeof(address));

    // connect(): (0) on success | (-1) on error
    int wait = waitActivity();

    if ((flagsfd == -1) || (connection == -1) || (wait == -1))
    {
        perror("Connection error");
        throw std::runtime_error("Connection Starting Failed.");
    }

    std::cout << "Starting client conection" << std::endl;
}

void Network::sendMessage(unsigned char *message, unsigned int messageLenght)
{
    if (messageLenght > MAX_SIZE)
    {
        throw std::runtime_error("Max message size exceeded in Send");
    }

    int sendMessage;

    do
    {
        sendMessage = send(sockfd, message, messageLenght, 0);
        if (sendMessage == -1 && ((errno != EWOULDBLOCK) || (errno != EAGAIN)))
        {
            perror("Send Message Error");
            throw std::runtime_error("Send failed");
        }
    } while (sendMessage != messageLenght);
}

void Network::showConfiguration()
{
    std::cout << std::endl;
    std::cout << "Network Configuration Values" << std::endl;
    std::cout << "Port: " << this->port << std::endl;
    std::cout << "Host: " << this->host << std::endl;
    std::cout << std::endl;
}

void Network::initConfiguration(int argc, char *argv[])
{
    int option;

    setPort(PORT);
    setHost((char *)LOCALHOST);

    while ((option = getopt(argc, argv, "p:h:")) != -1)
    {
        switch (option)
        {
        case 'p':
            setPort(atoi(optarg));
            break;
        case 'h':
            setHost(optarg);
            break;
        }
    }
}

void Network::clientConnection(int argc, char *argv[])
{
    initConfiguration(argc, argv);
    showConfiguration();
    newConnection();
    startConnection();
}

int Network::getPort()
{
    return this->port;
}

int Network::getSockFD()
{
    return this->sockfd;
}

int Network::waitActivity()
{
    struct pollfd pollfds[1];

    pollfds[0].fd = sockfd;
    pollfds[0].events = POLLIN;

    // poll(): (pollfd quantity) on success | (0) (-1) on error
    int polling = poll(pollfds, sizeof(pollfds) / sizeof(struct pollfd), 10);

    if (polling == -1)
    {
        return -1;
    }

    return 0;
}

char *Network::getHost()
{
    return this->host;
}

sockaddr_in Network::getAddress()
{
    return this->address;
}
