#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <strings.h>
#include <string.h>
#include <sys/epoll.h>
#include <error.h>
#include "thpool.h"
#include <time.h>
#include <ctype.h>

#define _GNU_SOURCE            
#include <sys/socket.h>


#define MAX_MSG_SIZE 512
#define MAX_USR_SIZE 9

typedef enum {false, true} bool;

int serverSocket;
struct sockaddr_in serverSockAddr;

int connected = 0;
int authenticated = 0;
char username_g[10];
char password_g[10];



bool startsWith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

void remove_newline(char *msg) {
	int len = strlen(msg);
	msg[len-1] = '\0';
}

void handle_ping(void *argt) {
	// int serverSocket = *((int *)argt);
	int timeOld = (int)time(NULL);
	int timeNow = timeOld;

	char *pingMsg = "/ping";

	while(connected) {
		if((timeNow = (int)time(NULL)) - timeOld > 20) {
			timeOld = timeNow;
			if(write(serverSocket, pingMsg, MAX_MSG_SIZE) == -1) {
				// printf("Server connection dFropped\n");
				close(serverSocket);
				connected = 0;
				authenticated = 0;
				break;
			}

		}
	}
}

bool valid_username(char *username) {
	int len = strlen(username);
	if(len > MAX_USR_SIZE) {
		return false;
	}
	for(int i = 0; i < len; i++) {
		if(!isalnum(username[i])) {
			return false;
		}
	}
	return true;
}

bool handle_authentication(char *msg) {
	char safetyBuffer[MAX_MSG_SIZE];
	strcpy(safetyBuffer, msg);
	char *userPass = safetyBuffer + strlen("/auth");

	// printf("Message before %s\n", msg);
	char *username = strtok(userPass, " ");
	char *password = strtok(NULL, " ");
	char *other = strtok(NULL, " ");
	if(!username || !password || other) {
		printf("Command usage: /auth <username> <password>\n");
		return false;
	}
	// strncpy(username_g, username, 10);
	// strncpy(password_g, password, 10);
	// printf("Username: %s, Password: %s\n Message after: %s\n", username, password, msg);
	return valid_username(username) && valid_username(password);
}

bool handle_whisper(char *msg) {
	char safetyBuffer[MAX_MSG_SIZE];
	strcpy(safetyBuffer, msg);
	char *command = strtok(safetyBuffer, " ");
	char *destination = strtok(NULL, " ");
	// char *message = strtok(NULL, "");

	return valid_username(destination);

}


void handle_output(void *argt) {

	// int serverSocket = *((int *)argt);

	char sendBuffer[MAX_MSG_SIZE];
	int c;

	while(connected) {
		bzero(sendBuffer, MAX_MSG_SIZE);
		// while ((c = getchar()) != '\n' && c != EOF);

		if(!fgets(sendBuffer, MAX_MSG_SIZE, stdin)) {
			printf("Error reading from stdin\n");
			continue;
		};
		// int len = strlen(sendBuffer);
		// sendBuffer[len-1] = '\0';
		remove_newline(sendBuffer);

		if(startsWith("/auth", sendBuffer)) {
			if(!handle_authentication(sendBuffer)) {
				continue;
			}
		}

		if(startsWith("/w", sendBuffer)) {
			if(!handle_whisper(sendBuffer)) {
				continue;
			}
		}

		// printf("Sending %s\n", sendBuffer);
		if(write(serverSocket, sendBuffer, MAX_MSG_SIZE) == -1) {
			printf("Server connection dropped\n");
			close(serverSocket);
			connected = 0;
			authenticated = 0;
			break;
		}

	}	
}

void handle_message(char *msg, int socket) {
	if(strcmp(msg, "/timeout") == 0) {
		printf("Connection timed out ...\n");
		close(socket);
		connected = 0;
		authenticated = 0;
	} else if(strcmp(msg, "/server_full") == 0) {
		printf("Server is full, try again later!\n");
		connected = 0;
		close(socket);
	} else if(strcmp(msg, "/no_access") == 0) {
		printf("Please login first!\n");
	} else if(strcmp(msg, "/quit_back") == 0) {
		printf("Quit succcesful.\n");
		connected = 0;
		close(socket);
	} else if(strcmp(msg, "/auth_succ") == 0) {
		printf("Auth successful\n");
	} else if(strcmp(msg, "/auth_fail") == 0) {
		printf("Auth failed\n");
	} else {
		printf(">%s\n", msg);
	}
}


void handle_input(void *argt) {
	// int serverSocket = *((int *)argt);
	int r;
	char recvBuffer[MAX_MSG_SIZE];

	while(connected) {
		bzero(recvBuffer, MAX_MSG_SIZE);

		if((r = read(serverSocket, recvBuffer, MAX_MSG_SIZE)) < 0) {
			// printf("Error read from server socket\n");
			connected = 0;
			break;
		}

		if(r == 0) {
			printf("Server dropped connection \n");
			close(serverSocket);
			connected = 0;
			break;
		}
		// printf("Received: %s\n", recvBuffer);
		handle_message(recvBuffer, serverSocket);


	}

}

void preConnection(threadpool thpool) {


	printf("Starting connection ... \n");

	if((serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		printf("socket failed\n");
		exit(1);
	}

	bzero(&serverSockAddr, sizeof(serverSockAddr));

	serverSockAddr.sin_family = AF_INET;
	serverSockAddr.sin_port = htons(3001);

	if(connect(serverSocket, (struct sockaddr *) &serverSockAddr, sizeof(serverSockAddr)) < 0) {
		printf("connect() failed\n");
		return;
	}
	printf("Connection successful!\n");
	connected = 1;
	thpool_add_work(thpool, (void *)handle_output, (void*)&serverSocket);
	thpool_add_work(thpool, (void *)handle_input, (void*)&serverSocket);
	thpool_add_work(thpool, (void *)handle_ping, (void *)&serverSocket);
}





int main() {

	// int serverSocket;

	// struct sockaddr_in serverSockAddr;

	char buffer[MAX_MSG_SIZE];
	threadpool thpool = thpool_init(6);
	// thpool_add_work(thpool, (void *)handle_output, (void*)&serverSocket);
	// thpool_add_work(thpool, (void *)handle_input, (void*)&serverSocket);
	// thpool_add_work(thpool, (void *)handle_ping, (void *)&serverSocket);
	while(1) {
		if(!connected) {
			bzero(buffer, MAX_MSG_SIZE);

			if(!fgets(buffer, MAX_MSG_SIZE, stdin)) {
				printf("Error reading from stdin (MAX SIZE IS 512)\n");
				continue;
			};
			remove_newline(buffer);
			// printf("What I read: %s\n", buffer);
			if(strcmp(buffer, "/connect") == 0) { 
				preConnection(thpool);
			}
			// if(startsWith("/connect", buffer)) {
			// 	handle_connection(thpool, buffer);
			// }
		}
	};

	thpool_destroy(thpool);
	// close(serverSocket);
	return 0;
}