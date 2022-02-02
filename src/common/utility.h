// Utility manager. Internal library
#pragma once
#ifndef UTILITY_H
#define UTILITY_H

#include <unistd.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <iostream>
#include <cstring>
#include <termios.h>
#include <limits>
#include <string>
#include <cctype>
#include "params.h"

static const char *allowedChars_username = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890_";
static const char *allowedChars_chat = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890 |\\! \"£%&/()='?ì^è+òàù,.é*ç°§;:_[]{}";

/**
 * Macro that makes use of "logError()" function in order to display a useful message for faster debugging purposes
 * and consequently terminate the execution of the program
 */
#define LOG_ERROR(message) logError(__FILE__, __FUNCTION__, __LINE__, message)

//------------------------------------------------------------------------------------------------------------------
/**
 * Macro that makes use of "logWarning()" function in order to display a useful message for faster debugging purposes
 * without interrupting execution of the program
 */
#define LOG_WARNING(message) logWarning(__FILE__, __FUNCTION__, __LINE__, message)

//------------------------------------------------------------------------------------------------------------------
/**
 * Function that displays a useful ERROR message for the developing team, reporting the file, function and line number
 * at which the ERROR occurred along with a custom ERROR message from the developers. Program execution stops after
 * the ERROR message has been displayed.
 *
 * @param file : program file in which the error occurred
 * @param function : function in which the error occurred
 * @param line : line in which the error occurred
 * @param message : custom error message
 **/
void logError(const char *file, const char *function, const int line, const char *message);

//------------------------------------------------------------------------------------------------------------------
/**
 * Function that displays a useful WARNING message for the developing team, reporting the file, function and line number
 * at which the WARNING occurred along with a custom WARNING message from the developers
 *
 * @param file : program file in which the warning occurred
 * @param function : function in which the warning occurred
 * @param line : line in which the warning occurred
 * @param message : custom warning message
 **/
void logWarning(const char *file, const char *function, const int line, const char *message);

//------------------------------------------------------------------------------------------------------------------
/**
 * Function for hide the cin writed by the user
 **/
void setStdinEcho(const bool enable);

//------------------------------------------------------------------------------------------------------------------
/**
 * Check insert a valid Char (At least one character)
 **/
std::string readStringValue(const std::string message);

//------------------------------------------------------------------------------------------------------------------
/**
 * Function used for receiving a message from a communicating partner
 * @param socket : socket of partner
 * @param buffer : buffer that's going to store the message coming from
 *                 the communicating partner
 * @return number of bytes sent by the communicating partner
 */
int receiveMessage(const int socket, unsigned char *buffer);

//------------------------------------------------------------------------------------------------------------------
/**
 * Controls if the username given by the client is valid or not, i.e.
 *          - "username" has got only allowed chars (see "allowedChars_username" in "utility.h")
 *          - len(username) <= USERNAME_LENGTH
 * @param username : username received from the client
 * @return 0 if success. 1 if the user name contain a non valid caracter or 2 if the user name doen's contain a valid private key.
 */
int usernameCheck(const std::string username);

//------------------------------------------------------------------------------------------------------------------
/**
 * Check if the private key of the username exist
 * @param fileName: name of the private key file
 * @return TRUE if the file is present. FALSE if the file doesn't exist.
 */
bool fileIsPresent(const std::string fileName);

//------------------------------------------------------------------------------------------------------------------
/**
 * Convert first letter in string to uppercase
 * @param string: string to uppercase
 */
std::string capitalize(std::string string);

//------------------------------------------------------------------------------------------------------------------
/**
 * Allocate memory of char size to an char pointer
 */
unsigned char *allocateValue(unsigned char *value, size_t size);

#endif // UTILITY_H