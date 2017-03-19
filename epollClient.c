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

#define _GNU_SOURCE            
#include <sys/socket.h>


#define MAX_MSG_SIZE 512


int connected = 0;

void remove_newline(char *msg) {
	int len = strlen(msg);
	msg[len-1] = '\0';
}

void handle_ping(void *argt) {
	int serverSocket = *((int *)argt);
	int timeOld = (int)time(NULL);
	int timeNow = timeOld;

	char *pingMsg = "/ping";

	while(1) {
		if((timeNow = (int)time(NULL)) - timeOld > 20) {
			timeOld = timeNow;
			if(write(serverSocket, pingMsg, MAX_MSG_SIZE) == -1) {
				// printf("Server connection dropped\n");
				break;
			}

		}
	}
}


void handle_output(void *argt) {

	int serverSocket = *((int *)argt);

	char sendBuffer[MAX_MSG_SIZE];

	while(1) {
		bzero(sendBuffer, MAX_MSG_SIZE);

		if(!fgets(sendBuffer, MAX_MSG_SIZE, stdin)) {
			printf("Error reading from stdin (MAX SIZE IS 512)\n");
			continue;
		};

		// int len = strlen(sendBuffer);
		// sendBuffer[len-1] = '\0';
		remove_newline(sendBuffer);


		if(write(serverSocket, sendBuffer, MAX_MSG_SIZE) == -1) {
			printf("Server connection dropped\n");
			connected = 1;
			break;
		}

	}	
}

void handle_message(char *msg, int socket) {
	if(strcmp(msg, "/timeout") == 0) {
		printf("Connection timed out ...\n");
		close(socket);
		connected = 1;
	} else {
		printf("Received: %s\n", msg);
	}
}


void handle_input(void *argt) {
	int serverSocket = *((int *)argt);
	int r;
	char recvBuffer[MAX_MSG_SIZE];

	while(1) {
		bzero(recvBuffer, MAX_MSG_SIZE);

		if((r = read(serverSocket, recvBuffer, MAX_MSG_SIZE)) < 0) {
			// printf("Error read from server socket\n");
			connected = 1;
			break;
		}

		if(r == 0) {
			printf("Server dropped connection \n");
			close(serverSocket);
		}
		// printf("Received: %s\n", recvBuffer);
		handle_message(recvBuffer, serverSocket);


	}

}

void preConnection(threadpool thpool) {
	int serverSocket;
	struct sockaddr_in serverSockAddr;

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

	connected = 1;
	thpool_add_work(thpool, (void *)handle_output, (void*)&serverSocket);
	thpool_add_work(thpool, (void *)handle_input, (void*)&serverSocket);
	thpool_add_work(thpool, (void *)handle_ping, (void *)&serverSocket);
}


int main() {

	// int serverSocket;

	// struct sockaddr_in serverSockAddr;

	char buffer[MAX_MSG_SIZE];

	// if((serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
	// 	printf("socket failed\n");
	// 	exit(1);
	// }

	// bzero(&serverSockAddr, sizeof(serverSockAddr));

	// serverSockAddr.sin_family = AF_INET;
	// serverSockAddr.sin_port = htons(3001);

	// if(connect(serverSocket, (struct sockaddr *) &serverSockAddr, sizeof(serverSockAddr)) < 0) {
	// 	printf("connect() failed\n");
	// 	exit(1);
	// }
	// int n;
	// pid_t curPid = getpid();
	// for(n = 0; n < 100; n++) {
	// 	sprintf(sendBuffer, "Process %d writing hello %d\n", curPid, n);
	// 	if(write(serverSocket, sendBuffer, MAX_MSG_SIZE) == -1) {
	// 			printf("Error writing to server socket\n");
	// 			exit(1);
	// 	}
	// }



	threadpool thpool = thpool_init(6);

	// thpool_add_work(thpool, (void *)handle_output, (void*)&serverSocket);
	// thpool_add_work(thpool, (void *)handle_input, (void*)&serverSocket);
	// thpool_add_work(thpool, (void *)handle_ping, (void *)&serverSocket);
	while(1) {
		if(!connected) {
			if(!fgets(buffer, MAX_MSG_SIZE, stdin)) {
				printf("Error reading from stdin (MAX SIZE IS 512)\n");
				continue;
			};
			remove_newline(buffer);
			// printf("What I read: %s\n", buffer);
			if(strcmp(buffer, "/connect") == 0) { 
				preConnection(thpool);
			}
		}
	};

	thpool_destroy(thpool);
	// close(serverSocket);
	return 0;
}