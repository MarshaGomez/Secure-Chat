#include "server.h"
using namespace std;

int totClients = 0;
unordered_map<string, Client> clients;


Client *getClient(const char *username)
{
	if (clients.bucket_count() != 0 && clients.find(username) != clients.end())
	{
		auto bucket = clients.bucket(username);
		// search inside bucket for usernames colliding inside that same bucket
		for (auto it = clients.begin(bucket); it != clients.end(bucket); ++it)
		{
			if (strncmp(it->second.username, username, USERNAME_LENGTH) == 0)
				return &(it->second);
		}
	}
	return nullptr;
}


void removeClient(const char *username)
{
	cout << "Now removing client " << username << " from hash-map " << endl;

	pthread_mutex_lock(&other_mutex);
	for (auto it = clients.begin(); it != clients.end(); it++)
	{
		if (strcmp(username, it->second.username) == 0)
		{
			clients.erase(it);
			--totClients;
			break;
		}
	}
	cout << "Current users still using the service : " << totClients << endl;
	pthread_mutex_unlock(&other_mutex);
}


EVP_PKEY *get_server_private_key()
{
	EVP_PKEY *server_prvkey;
	FILE *file = fopen((string(SERVER_PRV_KEY)).c_str(), "r");
	if (!file)
	{
		perror("fopen failed : cannot read server's private key\n");
		exit(1);
	}
	server_prvkey = PEM_read_PrivateKey(file, nullptr, nullptr, (void*)"server");
	fclose(file);

	return server_prvkey;
}


EVP_PKEY *get_client_pubkey(const string username)
{
	string path = string(DIR_PUBLIC_KEY) + username + string(".pem");
	FILE *file = fopen(path.c_str(), "r");
	if (!file)
	{
		removeClient(username.c_str());
		LOG_ERROR("fopen failed : no such public key present in public key directory");
	}
	EVP_PKEY *client_pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if (!client_pubkey)
	{
		removeClient(username.c_str());
		LOG_ERROR("PEM_read_PUBKEY returned no meaningful public key. Terminating thread now.");
	}
	fclose(file);

	return client_pubkey;
}


void append_thread(pthread_t thread_id, const Client *client)
{
	cout << "creating thread for handling new user" << endl;
	pthread_mutex_lock(&mutex);
	threads.push_back(thread_id);

	if (pthread_create(&threads.back(), nullptr, &userManager, (void *)client) != 0)
		LOG_ERROR("Error when creating new thread!");

	pthread_mutex_unlock(&mutex);
}


void forwardMessages()
{
	pthread_mutex_lock(&mutex);
	for (auto const &clientSender : clients)
	{
		while (!(clientSender.second.mb->inQueue.empty()))
		{
			Message message = clientSender.second.mb->inQueue.front();
			clientSender.second.mb->inQueue.pop();

			for (auto const &clientReceiver : clients)
			{
				if (strcmp(message.receiver, clientReceiver.second.username) == 0)
				{
					cout << message.sender << " sent a message (size = " << message.size << " Bytes ,type = " << message.message_type << ") to " << message.receiver << endl;
					clientReceiver.second.mb->outQueue.push(message);
				}
			}
		}
		bool quitting = (clientSender.second.status == QUITTING);
	}
	pthread_mutex_unlock(&mutex);
}


void getClientsList(Client *client)
{
	Cryptography *crypto = new Cryptography();
	int ret;

	string tmp = "";
	for (auto const &element : clients)
	{
		if (strcmp(element.second.username, client->username) != 0 && element.second.status == ONLINE)
			tmp += (element.second.username + string(", "));
	}

	unsigned int message_size = 1;
	if (strlen(tmp.c_str()) != 0)
		message_size = strlen(tmp.c_str()) - 1; // strlen(tmp) = strlen("client1, " + "client2, " + ... + "clientN, ") +
												//				 - 2 (because we want to remove the last ", ") +
												//				 + 1 (for '\0')

	char *tmp_ = (char *)tmp.c_str();
	tmp_[message_size - 1] = '\0';

	auto message = (unsigned char *)malloc(message_size);
	if (!message)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}
	memcpy(message, (unsigned char *)tmp_, message_size);

	auto aad = (unsigned char *)malloc(sizeof(unsigned int));
	if (!aad)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}
	memcpy(aad, (unsigned char *)&client->mb->sndCount, sizeof(unsigned int));

	auto buffer = (unsigned char *)malloc(MAX_SIZE);
	if (!buffer)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}

	ret = crypto->authEncrypt(	ONLINE_USERS, 
								aad, 
								sizeof(unsigned int), 
								message, 
								message_size, 
								client->sessionKey, 
								buffer);
	if (ret >= 0)
	{
		crypto->sendMessage(client->socket, ret, buffer);
		crypto->safeIncrement(client->mb->sndCount);
	}

	free(buffer);
	free(message);
	free(aad);
	free(crypto);
}


void reqToTalk(Client *client, unsigned char *message, int ret, unsigned char *aad)
{
	if (client->status == ONLINE)
	{
		Message *RTT = new Message;
		strncpy(RTT->sender, client->username, USERNAME_LENGTH);
		RTT->sender[USERNAME_LENGTH] = '\0';
		memcpy(RTT->receiver, message, ret);
		RTT->receiver[ret] = '\0';

		RTT->size = NONCE_SIZE;
		RTT->message = (unsigned char *)malloc(RTT->size);
		if (!RTT->message)
		{
			removeClient(client->username);
			LOG_ERROR("malloc failed");
		}
		memcpy(RTT->message, aad + sizeof(unsigned int), RTT->size);

		Client *client_RTT_receiver = getClient((const char *)RTT->receiver);

		if (!client_RTT_receiver ||
			client_RTT_receiver->status != ONLINE ||
			client_RTT_receiver == client ||
			usernameCheck(RTT->receiver) != 0)
		{
			cout << "thread(" << client->username << ") : "
				 << " user " << RTT->receiver << " not found." << endl;
			strncpy(RTT->receiver, client->username, USERNAME_LENGTH);
			RTT->receiver[USERNAME_LENGTH] = '\0';

			RTT->message_type = UNKNOWN_USER;
			client->status = ONLINE;
		}
		else
		{
			client->status = WAITING;
			RTT->message_type = REQUEST_TO_TALK;
			cout << "thread(" << client->username << ") : "
				 << "forwarding REQ TO TALK to " << RTT->receiver << endl;
		}

		client->mb->inQueue.push(*RTT);
	}
}


void acceptRTT(	Client *client, 
				unsigned char *message, 
				EVP_PKEY *client_pubkey, 
				unsigned int aadlen, 
				unsigned char *aad, 
				int ret)
{
	Cryptography *crypto = new Cryptography();
	if (client->status != CHATTING)
	{
		Message *key = new Message;
		char peerusername[USERNAME_LENGTH + 1];
		strncpy(key->sender, client->username, USERNAME_LENGTH);
		peerusername[USERNAME_LENGTH] = '\0';
		memcpy(key->receiver, message, USERNAME_LENGTH + 1);
		memcpy(client->peer_username, message, USERNAME_LENGTH + 1);

		BIO *bio = BIO_new(BIO_s_mem());
		PEM_write_bio_PUBKEY(bio, client_pubkey);
		char *mypubkey_buf = NULL;
		long pubkey_size = BIO_get_mem_data(bio, &mypubkey_buf);

		key->size = pubkey_size + aadlen + sizeof(long) - sizeof(unsigned int);
		key->message = (unsigned char *)malloc(key->size);
		if (!key->message)
		{
			removeClient(client->username);
			LOG_ERROR("malloc failed");
		}

		memcpy(key->message,
			   (unsigned char *)&pubkey_size,
			   sizeof(long));

		memcpy(key->message + sizeof(long),
			   mypubkey_buf,
			   pubkey_size);

		// put signed (by current client) ecdhpubkey in msg for peer
		memcpy(key->message + pubkey_size + sizeof(long),
			   aad + sizeof(unsigned int),
			   aadlen - sizeof(unsigned int));
		key->message_type = REQUEST_ACCEPTED;

		// read peer's public key
		string filename = DIR_PUBLIC_KEY + (string)key->receiver + ".pem";
		FILE *file = fopen(filename.c_str(), "r");
		if (!file)
		{
			removeClient(client->username);
			LOG_ERROR("fopen failed : wrong path?");
		}
		EVP_PKEY *peer_pubkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
		if (!peer_pubkey)
		{
			removeClient(client->username);
			LOG_ERROR("PEM_read_PUBKEY failed");
		}
		BIO *peer_bio = BIO_new(BIO_s_mem());
		PEM_write_bio_PUBKEY(peer_bio, peer_pubkey);
		char *peer_pubkey_buf = NULL;
		pubkey_size = BIO_get_mem_data(peer_bio, &peer_pubkey_buf);

		unsigned int aad_len = (unsigned int)pubkey_size + sizeof(unsigned int);
		unsigned char *aad_ = (unsigned char *)malloc(aad_len);
		if (!aad_)
		{
			removeClient(client->username);
			LOG_ERROR("malloc failed");
		}

		memcpy(aad_, (unsigned char *)&client->mb->sndCount, sizeof(unsigned int));
		memcpy(aad_ + sizeof(unsigned int), peer_pubkey_buf, (int)pubkey_size);

		auto buffer = (unsigned char *)malloc(MAX_SIZE);
		if (!buffer)
		{
			removeClient(client->username);
			LOG_ERROR("malloc failed");
		}

		int messageSize = crypto->authEncrypt(	CHAT_SESSION, 
												aad_, 
												aad_len, 
												message, 
												ret, 
												client->sessionKey, 
												buffer);
		if (messageSize >= 0)
		{
			// send client pubkey and ecdhpubkey to peer
			client->mb->inQueue.push(*key);

			// send peerpubkey to client
			crypto->sendMessage(client->socket, messageSize, buffer);
			crypto->safeIncrement(client->mb->sndCount);
			client->status = CHATTING;
		}
		fclose(file);
		BIO_free(bio);
		BIO_free(peer_bio);
		free(peer_pubkey);
		free(aad_);
		free(crypto);
	}
}


void refuseRTT(Client *client, const unsigned char *message)
{
	if (client->status != CHATTING)
	{
		Message *rtt_reject = new Message;
		strncpy(rtt_reject->sender, client->username, USERNAME_LENGTH);
		rtt_reject->sender[USERNAME_LENGTH] = '\0';

		memcpy(rtt_reject->receiver, message, USERNAME_LENGTH + 1);
		rtt_reject->size = 0;
		rtt_reject->message_type = REQUEST_REFUSED;
		client->status = ONLINE;
		client->mb->inQueue.push(*rtt_reject);
		cout << "Forwarding refuse to " << rtt_reject->receiver << endl;
	}
}


void chat(	Client *client, 
			unsigned char *message, 
			unsigned int aadlen, 
			unsigned char *aad)
{
	if (client->status == CHATTING)
	{
		Message *text = new Message;
		strncpy(text->sender, client->username, USERNAME_LENGTH);
		text->sender[USERNAME_LENGTH] = '\0';
		memcpy(text->receiver, message, USERNAME_LENGTH + 1);

		text->size = aadlen - sizeof(unsigned int);
		text->message = (unsigned char *)malloc(text->size);
		if (!text->message)
		{
			removeClient(client->username);
			LOG_ERROR("malloc failed");
		}

		memcpy(text->message, aad + sizeof(unsigned int), text->size);
		text->message_type = TEXT_MESSAGE;
		client->mb->inQueue.push(*text);
	}
}


void sendPubKey(Client *client, 
				unsigned char *message, 
				unsigned int aadlen, 
				unsigned char *aad)
{
	Message *key = new Message;
	strncpy(key->sender, client->username, USERNAME_LENGTH);
	key->sender[USERNAME_LENGTH] = '\0';
	memcpy(client->peer_username, message, USERNAME_LENGTH + 1);
	memcpy(key->receiver, message, USERNAME_LENGTH + 1);
	key->size = aadlen - sizeof(unsigned int);
	key->message = (unsigned char *)malloc(key->size);
	if (!key->message)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}
	memcpy(key->message, aad + sizeof(unsigned int), key->size);
	key->message_type = CHAT_SESSION;
	client->mb->inQueue.push(*key);
	client->status = CHATTING;
}


void exitChat(Client *client, unsigned char *message)
{
	Cryptography *crypto = new Cryptography();
	auto buffer = (unsigned char *)malloc(MAX_SIZE);
	if (client->status == CHATTING)
	{
		Message *chatEndNotification = new Message;
		strncpy(chatEndNotification->sender, client->username, USERNAME_LENGTH);
		chatEndNotification->sender[USERNAME_LENGTH] = '\0';
		strncpy(chatEndNotification->receiver, client->peer_username, USERNAME_LENGTH + 1);
		chatEndNotification->size = 0;
		chatEndNotification->message_type = CHAT_CLOSED;
		client->mb->inQueue.push(*chatEndNotification);

		int messageSize = crypto->authEncrypt(CHAT_CLOSED,
											  (unsigned char *)&client->mb->sndCount,
											  sizeof(unsigned int),
											  (unsigned char *)client->username,
											  strlen(client->username),
											  client->sessionKey,
											  buffer);
		if (messageSize >= 0)
		{
			crypto->sendMessage(client->socket, messageSize, buffer);
			crypto->safeIncrement(client->mb->sndCount);
		}
		client->status = ONLINE;
	}
	free(buffer);
	free(crypto);
}


int main(int argc, char *argv[])
{
	uint16_t port = PORT;
	if (argc >= 2 && argc <= 3)
	{
		int option = getopt(argc, argv, "p:");
		switch (option)
		{
			case 'p':
				port = atoi(optarg);
				break;
			default:
				cout << "No valid port entered. Using default port (8080)\n"
					<< endl;
		}

		cout << "Using port " << int(port) << " ... \n";
	}

	Server *server = new Server(port);
	int server_sd = server->get_server_sd();
	struct sockaddr_in server_address = server->get_server_address();
	int addrlen = sizeof(server_address);
	if (listen(server_sd, MAX_CLIENTS) < 0)
		LOG_ERROR("listen failed.");
	cout << "Listening for new clients ... " << endl;

	while (1)
	{
		int client_sd;
		client_sd = accept(server_sd, (struct sockaddr *)&server_address, (socklen_t *)&addrlen);
		if (client_sd < 0)
		{
			if (errno != EWOULDBLOCK)
				LOG_ERROR("accept failed");
		}
		else
		{
			// REMEMBER TO CLOSE SOCKET ONCE YOU'RE DONE WITH THE CLIENT!!!
			cout << "New client has connected!" << endl;
			// creating new Client object for the newly connected client
			struct Client *CLIENT = new Client;
			struct MessageBox *MB = new MessageBox;
			CLIENT->mb = MB;
			CLIENT->socket = client_sd;

			pthread_t thread_id;
			append_thread(thread_id, CLIENT);
		}
		forwardMessages();
	}

	return 0;
}


void *forwardingManager(void *CLIENT)
{
	Cryptography *crypto = new Cryptography();
	auto client = (Client *)CLIENT;
	int ret;
	unsigned char *buffer = (unsigned char *)malloc(MAX_SIZE);
	if (!buffer) LOG_ERROR("malloc failed");
	unsigned char *aad = (unsigned char *)malloc(MAX_SIZE);
	if (!aad) LOG_ERROR("malloc failed");

	pthread_mutex_lock(&mutex);
	bool done = (client->status == QUITTING);
	pthread_mutex_unlock(&mutex);
	while (!done)
	{
		pthread_mutex_lock(&mutex);
		if (!(client->mb->outQueue.empty()))
		{
			Message message = client->mb->outQueue.front();
			if (message.size <= MAX_SIZE)
			{
				client->mb->outQueue.pop();
				memcpy(	aad, 
						(unsigned char *)&client->mb->sndCount, 
						sizeof(unsigned int));

				memcpy(	aad + sizeof(unsigned int), 
						message.message, 
						message.size);
				
				ret = crypto->authEncrypt(	message.message_type, 
											aad, 
											message.size + sizeof(unsigned int), 
											(unsigned char *)message.sender, 
											strlen(message.sender) + 1, 
											client->sessionKey, 
											buffer);
				if (ret >= 0)
				{
					crypto->sendMessage(client->socket, ret, buffer);
					crypto->safeIncrement(client->mb->sndCount);
				}
				switch (message.message_type)
				{
					case REQUEST_REFUSED:
					{
						client->status = ONLINE;
						break;
					}

					case REQUEST_TO_TALK:
					{
						client->status = WAITING;
						break;
					}

					case CHAT_CLOSED:
					{
						client->status = ONLINE;
						break;
					}
				}
			}
		}
		done = (client->status == QUITTING);
		pthread_mutex_unlock(&mutex);
	}
	free(buffer);
	free(aad);
	free(crypto);
	cout << "queueManager(" << client->username << ") terminating." << endl;
	pthread_exit(NULL);
	return NULL;
}


void *userManager(void *CLIENT)
{
	Cryptography *crypto = new Cryptography();
	auto client = (Client *)CLIENT;
	int ret;
	unsigned char *buffer = (unsigned char *)malloc(MAX_SIZE);
	if (!buffer)
		LOG_ERROR("malloc failed");

	// 1. Get CLIENT_HELLO message from client
	int size = crypto->receiveMessage(client->socket, buffer);
	if (size <= 0)
		LOG_ERROR("Error when receiving CLIENT_HELLO message from client");

	unsigned int signed_message_length = *(unsigned int *)buffer;
	unsigned int client_nonce = *(unsigned int *)(buffer + sizeof(unsigned int) + signed_message_length);
	unsigned int username_size = size - (2 * sizeof(unsigned int) + signed_message_length);
	char *username = (char *)(buffer + sizeof(unsigned int) + signed_message_length + sizeof(unsigned int));
	username[username_size] = '\0';
	if (usernameCheck(username) == 0)
		strncpy(client->username, username, strlen(username));
	else
		LOG_ERROR("Provided username is not valid.");

	pthread_mutex_lock(&mutex);
	Client *tmp = getClient(client->username);
	if (tmp != nullptr)
	{
		LOG_WARNING(string(string("Client ") + string(username) +
						   string(" already exists! One client at a time is allowed for each user!"))
						.c_str());
		close(client->socket);
		pthread_mutex_unlock(&mutex);
		pthread_exit(nullptr); // terminating thread
	}

	if (totClients >= MAX_CLIENTS)
	{
		LOG_WARNING("Too many clients connected. Terminating thread.");
		close(client->socket);
		pthread_mutex_unlock(&mutex);
		pthread_exit(nullptr);
	}

	/* in python-like formalism, it'd be like clients[ client->username ].append(client),
	 *  since for each index there is a bucket containing elements (like a python list) that have collided
	 *  on that index. For more info on inserting things in unordered_map consult the following link :
	 *  https://www.cplusplus.com/reference/unordered_map/unordered_map/insert/
	 **/
	clients.insert({{client->username, *client}});
	cout << client->username << " has just logged in!" << endl;
	++totClients;

	pthread_mutex_unlock(&mutex);
	client = getClient(client->username);

	// 2. AUTHENTICATION PHASE & DH Key exchange :
	unsigned char *clear_msg = (unsigned char *)malloc(size - sizeof(unsigned int) - signed_message_length);
	if (!clear_msg)
	{
		removeClient(client->username);
		LOG_ERROR("Error when allocating memory for the cleartext message buffer");
	}

	// 2.A Verify client signature
	EVP_PKEY *client_pubkey = get_client_pubkey(string(client->username));
	if (!client_pubkey)
	{
		removeClient(client->username);
		LOG_ERROR("get_client_pubkey returned no meaningful client's public key");
	}
	ret = crypto->digsignVerify(client_pubkey, buffer, size, clear_msg);
	if (ret < 0)
	{
		removeClient(client->username);
		LOG_ERROR("Signature verification failed.");
	}

	cout << "Concluded pt. 2.A (verify client signature)" << endl;

	// 2.B LOAD CERTIFICATE (to be included in SERVER_REPLY message)
	X509 *server_certificate;
	crypto->loadCertificate(server_certificate, (char *)SERVER_CERTIFICATE);

	BIO *bio_cert = BIO_new(BIO_s_mem());
	if (!bio_cert)
	{
		removeClient(client->username);
		LOG_ERROR("BIO_new failed creating new BIO object");
	}
	ret = PEM_write_bio_X509(bio_cert, server_certificate);
	if (!ret)
	{
		removeClient(client->username);
		LOG_ERROR("Serialization of X509 cert in BIO mem object failed");
	}

	unsigned char *serialized_server_certificate = nullptr;
	long server_certificate_size = BIO_get_mem_data(bio_cert, &serialized_server_certificate);
	if (server_certificate_size <= 0)
	{
		removeClient(client->username);
		LOG_ERROR("BIO_get_mem_data failed");
	}

	cout << "Concluded pt. 2.B (load server's X509 cert. and serialize it)" << endl;

	// 2.C GENERATE SERVER NONCE (to be included in SERVER_REPLY message)
	unsigned int server_nonce = *(unsigned int*)crypto->newNonce();
	cout << "Concluded pt. 2.C (generate server nonce)" << endl;

	// 2.D Diffie-Hellman
	unsigned char *server_dh_pubkey = nullptr;
	BIO *bio_dh = BIO_new(BIO_s_mem());
	if (!bio_dh)
	{
		removeClient(client->username);
		LOG_ERROR("BIO_new failed creating new BIO object");
	}

	EVP_PKEY *server_dh_prvkey = crypto->dhGenerateKey();
	if (!server_dh_prvkey)
	{
		removeClient(client->username);
		LOG_ERROR("DHKeyGenerate didn't return a meaningful prv key ");
	}
	ret = PEM_write_bio_PUBKEY(bio_dh, server_dh_prvkey);
	if (!ret)
	{
		removeClient(client->username);
		LOG_ERROR("PEM_write_bio_PUBKEY failed");
	}
	long server_dh_pubkey_size = BIO_get_mem_data(bio_dh, &server_dh_pubkey);
	if (server_dh_pubkey_size <= 0)
	{
		removeClient(client->username);
		LOG_ERROR("BIO_get_mem_data failed");
	}

	cout << "Concluded pt. 2.D" << endl;

	//   2.E. Retrieve prv key of server
	EVP_PKEY *server_prvkey = get_server_private_key();
	if (!server_prvkey)
	{
		removeClient(client->username);
		LOG_ERROR("get_server_private_key didn't return a meaningful server prv key");
	}

	cout << "Concluded pt. 2.E (get server's private key)" << endl;

	// 2.F Prepare cleartext message to be signed
	if (NONCE_LENGTH + NONCE_LENGTH + server_dh_pubkey_size > MAX_SIZE)
	{
		removeClient(client->username);
		LOG_ERROR("Message too big");
	}
	free(clear_msg);
	clear_msg = (unsigned char *)malloc(NONCE_LENGTH + NONCE_LENGTH + server_dh_pubkey_size);
	int written = 0;
	memcpy(clear_msg, &client_nonce, NONCE_LENGTH);
	written += NONCE_LENGTH;
	memcpy(clear_msg + written, &server_nonce, NONCE_LENGTH);
	written += NONCE_LENGTH;
	memcpy(clear_msg + written, server_dh_pubkey, server_dh_pubkey_size);
	written += server_dh_pubkey_size;

	cout << "Concluded pt. 2.F (prepared cleartext message)" << endl;

	// 2.G Sign message
	unsigned char *server_signed_message = (unsigned char *)malloc(MAX_SIZE);
	signed_message_length = crypto->digsignSign(server_prvkey, 
												clear_msg, 
												written, 
												server_signed_message);

	cout << "Concluded pt. 2.G (just signed the message)" << endl;

	// 2.H Send server X509 certificate and SERVER_REPLY message
	crypto->sendMessage(client->socket, server_certificate_size, serialized_server_certificate);
	cout << "Sent certificate to " << client->username << endl;
	crypto->sendMessage(client->socket, signed_message_length, server_signed_message);

	cout << "Concluded pt. 2.H (sent SERVER_REPLY message to " << client->username << ")" << endl;

	// 2.I Get CLIENT_REPLY message
	ret = crypto->receiveMessage(client->socket, buffer);
	if (ret <= 0)
	{
		removeClient(client->username);
		LOG_ERROR("Error when receiving CLIENT_REPLY message from client");
	}
	signed_message_length = ret;
	unsigned int signature_size = *(unsigned int *)buffer;
	if (CRYPTO_memcmp((buffer + sizeof(unsigned int) + signature_size), (void *)&server_nonce, NONCE_LENGTH) != 0)
	{
		removeClient(client->username);
		LOG_ERROR("Server nonce received from client message is not correct!");
	}

	cout << "Concluded pt. 2.I (got CLIENT_REPLY message)" << endl;

	//  2.J Get DH pubkey of client & verify its signature
	EVP_PKEY *client_dh_pubkey;
	size = crypto->digsignVerify(client_pubkey, buffer, signed_message_length, clear_msg);
	if (size <= 0)
	{
		removeClient(client->username);
		LOG_ERROR("crypto->digsignVerify reports error in signed message coming from client");
	}
	BIO *bio = BIO_new(BIO_s_mem());
	BIO_write(bio, clear_msg + NONCE_LENGTH, size - NONCE_LENGTH);
	client_dh_pubkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	cout << "Concluded pt. 2.J" << endl;

	// 2.K Generate session key
	client->sessionKey = (unsigned char *)malloc(EVP_MD_size(crypto->md));
	if (!client->sessionKey)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}
	crypto->secretDerivation(server_dh_prvkey, client_dh_pubkey, client->sessionKey);

	cout << "Concluded pt. 2.K (client-server session key generated)" << endl;

	cout << "Now preparing to serve client for chatting service..." << endl;
	client->status = ONLINE;

	// 3. Send ONLINE clients list to client
	getClientsList(client);
	cout << "Concluded pt. 3 (sent clients list to client)" << endl;

	// 4. Creating new thread for managing the message forwarding part
	pthread_t forwardingmanager;
	if (pthread_create(&forwardingmanager, NULL, &forwardingManager, (void *)client) != 0)
	{
		removeClient(client->username);
		LOG_ERROR("pthread_create failed in creating the \"forwarding manager\" thread");
	}

	// 5. Manage messages from client
	short messageType;
	unsigned int messageSize;
	unsigned char *message = (unsigned char *)malloc(MAX_SIZE);
	if (!message)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}
	
	unsigned int aadSize;
	unsigned char *aad = (unsigned char *)malloc(MAX_SIZE);
	if (!aad)
	{
		removeClient(client->username);
		LOG_ERROR("malloc failed");
	}


	pthread_mutex_lock(&mutex);
	bool done = (client->status == QUITTING);
	pthread_mutex_unlock(&mutex);
	while (!done)
	{
		messageSize = crypto->receiveMessage(client->socket, buffer);
		pthread_mutex_lock(&mutex);
		if (client->status != QUITTING && messageSize > 0)
		{
			unsigned int received_counter = *(unsigned int *)(buffer + MSGHEADER);

			if (received_counter == client->mb->receiveCount)
			{
				ret = crypto->authDecrypt(	buffer, 
											messageSize, 
											client->sessionKey, 
											messageType, 
											aad, 
											aadSize, 
											message);
				if (ret <= 0)
				{
					removeClient(client->username);
					LOG_ERROR("authDecrypt returned no meaningful output");
				}
				crypto->safeIncrement(client->mb->receiveCount);

				switch (messageType)
				{
					case EXITED:
					{
						client->status = QUITTING;
						break;
					}

					case ONLINE_USERS:
					{
						getClientsList(client);
						break;
					}

					case REQUEST_TO_TALK:
					{
						if(ret <= USERNAME_LENGTH)
							reqToTalk(client, message, ret, aad);
						break;
					}

					case REQUEST_ACCEPTED:
					{
						cout << "received accept " << endl;
						acceptRTT(client, message, client_pubkey, aadSize, aad, ret);
						break;
					}

					case REQUEST_REFUSED:
					{
						cout << client->username << " refused Request To Talk " << endl;
						refuseRTT(client, message);
						break;
					}

					case TEXT_MESSAGE:
					{
						chat(client, message, aadSize, aad);
						break;
					}

					case CHAT_SESSION:
					{
						sendPubKey(client, message, aadSize, aad);
						break;
					}

					case CHAT_CLOSED:
					{
						exitChat(client, message);
						break;
					}

					default:
						LOG_WARNING((string("thread(") + string(client->username) + string(") : no valid message type was received.")).c_str());
				}
			}
		}
		done = (client->status == QUITTING);
		pthread_mutex_unlock(&mutex);
	}

	pthread_join(forwardingmanager, nullptr);
	free(aad);
	free(message);
	EVP_PKEY_free(client_pubkey);
	free(buffer);
	close(client->socket);

	removeClient(client->username);
	cout << "thread(" << client->username << ") terminating." << endl;
	
	pthread_exit(nullptr);
	return nullptr;
}
