#include "utility.h"

void logError(const char *file, const char *function, const int line, const char *message)
{
    std::cerr << std::endl
              << "[" << file << ", " << function << "(), line " << line << "] ERROR : " << message << std::endl
              << std::endl;
    perror("");
    pthread_exit(nullptr);
}

void logWarning(const char *file, const char *function, const int line, const char *message)
{
    std::cerr << std::endl
              << "[" << file << ", " << function << "(), line " << line << "] WARNING : " << message << std::endl
              << std::endl;
}

void setStdinEcho(const bool enable = true)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

std::string readStringValue(const std::string message)
{
    std::string value;
    std::cout << message;

    do
    {
        getline(std::cin, value);
        if (value.length() == 0)
        {
            std::cout << "ERROR: Insert at least one character." << std::endl;
            std::cout << message;
        }
    } while (value.length() == 0);

    return value;
}

int receiveMessage(const int socket, unsigned char *buffer)
{
    int ret;
    int tot_num_bytes_to_be_received;

    ret = recv(socket, &tot_num_bytes_to_be_received, sizeof(uint32_t), 0);
    if (ret < 0)
        LOG_ERROR("Couldn't correctly receive the size of message.");
    else
    {
        tot_num_bytes_to_be_received = ntohl(tot_num_bytes_to_be_received);
        if (tot_num_bytes_to_be_received > MAX_SIZE)
        {
            LOG_WARNING("Message too long. Aborting receive.");
            return 0;
        }
        ret = recv(socket, buffer, tot_num_bytes_to_be_received, 0);
        if (ret < 0)
            LOG_ERROR("Couldn't correctly receive message.");
        return ret;
    }

    return 0;
}

int usernameCheck(const std::string username)
{
    /*
     * Username is non-valid if :
     * --- it is empty, i.e. "";
     * --- first char is non-numeric;
     * --- it doesn't use allowed chars
     * --- it has more than USERNAME_LENGTH + 1 (i.e. '\0') chars
     */

    int result = 1;

    int n = username.length();

    // declaring character array
    char usernameToChar[n + 1];

    // copying the contents of the
    // string to char array
    strncpy(usernameToChar, username.c_str(),n);
    usernameToChar[n] = '\0';

    if (strlen(usernameToChar) == 0 ||
        (usernameToChar[0] >= '0' && usernameToChar[0] <= '9') ||
        strspn(usernameToChar, allowedChars_username) < strlen(usernameToChar) ||
        strlen(usernameToChar) > USERNAME_LENGTH)
    {
        result = 1;
    }
    else
    {
        const bool filePresent = fileIsPresent(username);
        if (filePresent)
            result = 0; // If the name is a valid name and the private key is present
        else
            result = 2; // If the user private key is not present the function returns 2
    }
    return result;
}

bool fileIsPresent(const std::string username)
{
    DIR *directory;
    struct dirent *pointer; // pointer represent directory stream
    bool result = false;
    std::string fileName = username + ".pem";
    if ((directory = opendir(DIR_PRIVATE_KEY)) != NULL)
    {
        while ((pointer = readdir(directory)) != NULL)
        {
            if (fileName == pointer->d_name)
            {
                result = true;
                break;
            }
        }
        closedir(directory);
    }

    return result;
}

std::string capitalize(std::string string)
{
    string[0] = toupper(string[0]);
    return string;
}

unsigned char *allocateValue(unsigned char *value, size_t size)
{
    value = (unsigned char *)malloc(size);

    if (!value)
    {
        throw std::runtime_error("An error occurred while tries to allocate a block of uninitialized memory to a pointer.");
    }
    else
    {
        return value;
    }
}
