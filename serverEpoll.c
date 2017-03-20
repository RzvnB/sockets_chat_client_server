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


#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <sys/socket.h>

#define MAX_MSG_SIZE 512
#define PORT 3001
#define MAX_PENDING 20
#define MAX_EVENTS 200
#define MAX_CLIENTS 200

typedef enum {false, true} bool;


struct message_handle {
	char *msg;
	int size;
	int source;
};

struct connection_handle {
	int socket;
	int lastPingTime;
	bool authenticated;
	uint32_t usernameHash;
	char userName[10];
};



char database[1000][10];
char takenUsers[1000];

static struct connection_handle clientConnections[MAX_CLIENTS];
// static int clientSockets[MAX_CLIENTS];
static int emptyIdx = 0;

uint32_t adler32(const void *buf, size_t buflength);


void broadcastMsg(char *msg, int r, int sourceSocket) {
	for(int i = 0; i < emptyIdx; i++) {
		if(clientConnections[i].socket != sourceSocket) {
			if(clientConnections[i].authenticated) {
			// printf("Sending -> %s <- to descriptor %d\n", msg, clientSockets[i]);
				if(write(clientConnections[i].socket, msg, r) != r) {
					printf("Error writing to socket\n");
					exit(1);
				}
			}
		}
	}
}


bool startsWith(const char *pre, const char *str)
{
    size_t lenpre = strlen(pre),
           lenstr = strlen(str);
    return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

int find_client_with_socket(int socket) {
	for(int i = 0; i < emptyIdx; i++) {
		if(clientConnections[i].socket == socket) {
			return i;
		}
	}
	return 0;
}

void handle_message(void *argt) {
	struct message_handle *args = argt;

	char *msg = args->msg;
	printf("Message is %s\n", msg);
	if(strcmp(msg, "/ping") == 0) {
		// printf("Received ping \n");
		for(int i = 0; i < emptyIdx; i++) {
			if(clientConnections[i].socket == args->source) {
				clientConnections[i].lastPingTime = (int)time(NULL);
			}
		}
	} else if(strcmp(msg, "/quit") == 0) {
		for(int i = 0; i < emptyIdx; i++) {
			if(clientConnections[i].socket == args->source) {
				write(clientConnections[i].socket, "/quit_back", MAX_MSG_SIZE);
				printf("Closing connection on descriptor %d\n", clientConnections[i].socket);
				close(clientConnections[i].socket);
				if(clientConnections[i].authenticated) {
					clientConnections[i].authenticated = false;
					takenUsers[clientConnections[i].usernameHash] = 0;
				}
				memmove(&clientConnections[i], &clientConnections[i+1], emptyIdx-(i+1));
				emptyIdx--;
			}
		}

	} else if(startsWith("/auth", msg)) {
		printf("I am hereererere\n");
		msg = msg + strlen("/auth");
		int clIdx = find_client_with_socket(args->source);
		char *userName = strtok(msg, " ");
		char *passWord = strtok(NULL, " ");
		printf("Username: %s, Password: %s\n", userName, passWord);
		uint32_t hash = adler32(userName, strlen(userName)) % 1000;
		if(strcmp(database[hash], passWord) == 0) {
			if(takenUsers[hash] != 1) {
				clientConnections[clIdx].authenticated = true;
				takenUsers[hash] = 1;
				clientConnections[clIdx].usernameHash = hash;
				write(clientConnections[clIdx].socket, "/auth_succ", MAX_MSG_SIZE);
			} else {
				write(clientConnections[clIdx].socket, "/auth_fail", MAX_MSG_SIZE);
			}
			// printf("Auth successful\n");
		} else {
			write(clientConnections[clIdx].socket, "/auth_fail", MAX_MSG_SIZE);
			// printf("Auth unsuccessful\n");
		}

	} else {
		for(int i = 0; i < emptyIdx; i++) {
			if(clientConnections[i].socket == args->source) {
				if(clientConnections[i].authenticated) {
					broadcastMsg(msg, args->size, args->source);
				} else {
					write(clientConnections[i].socket, "/no_access", MAX_MSG_SIZE);
				}
			}
		}
	}
}


uint32_t adler32(const void *buf, size_t buflength) {
     const uint8_t *buffer = (const uint8_t*)buf;

     uint32_t s1 = 1;
     uint32_t s2 = 0;

     for (size_t n = 0; n < buflength; n++) {
        s1 = (s1 + buffer[n]) % 65521;
        s2 = (s2 + s1) % 65521;
     }     
     return (s2 << 16) | s1;
}


void handle_auth() {

}

void check_idle(void *argt) {
	int timeNow;
	char *timeOutMsg = "/timeout";
	int len = strlen(timeOutMsg);
	while(1) {
		for(int i = 0; i < emptyIdx; i++) {
			timeNow = (int)time(NULL);
			if(timeNow - clientConnections[i].lastPingTime > 31) {
				if(write(clientConnections[i].socket, timeOutMsg, len) != len) {
					printf("Error writing timeout message!\n");
				}
				printf("Closing connection on descriptor %d\n", clientConnections[i].socket);
				close(clientConnections[i].socket);
				if(clientConnections[i].authenticated) {
					clientConnections[i].authenticated = false;
					takenUsers[clientConnections[i].usernameHash] = 0;
				}
				memmove(&clientConnections[i], &clientConnections[i+1], emptyIdx-(i+1));
				emptyIdx--;
			}	
		}
		sleep(5);
	}
}

// void print_database() {
// 	for(int i = 0; i < 1000; i++) {
// 		if(char[i]) {
// 			printf("Password: %s\n", char[i]);
// 		}
// 	}
// }


int main() {

	FILE *f = fopen("credentials.txt", "a+");

	if(!f) {
		printf("Error opening credentials file!\n");
		exit(1);
	}

	
	uint32_t hash;
	char unameBuf[10];
	char passBuf[10];

	while(fscanf(f, "%s %s\n", unameBuf, passBuf) != EOF) {
		// printf("%s sadface %s\n", unameBuf, passBuf);
		hash = adler32(unameBuf, strlen(unameBuf)) % 1000;
		// printf("hashcode - %d\n", hash % 1000);
		strcpy(database[hash], passBuf);
		printf("password in databse: %s\n", database[hash]);
	};

	struct epoll_event ev, events[MAX_EVENTS];

	int listenSock, clientSock, nfds, epollfd;

	int n, i;

	socklen_t clientLen;

	struct message_handle *args = malloc(sizeof(*args));

	char *serverFullMsg = "/server_full";
	int srvFullMsgLen = strlen(serverFullMsg);

	if(!args) {
		perror("Failed allocation for message handle");
		exit(1);
	}

	// for(i = 0; i < MAX_CLIENTS; i++) {
	// 	if(!clientConnections[i].socket) {
	// 		printf("EMPTY");
	// 	}
	// }

	struct sockaddr_in serverSockAddr, clientSockAddr;

	bzero(&events, sizeof(events));
	bzero(&serverSockAddr, sizeof(serverSockAddr));
	bzero(&clientSockAddr, sizeof(clientSockAddr));

	if((listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket()");
		exit(1);
	}

	serverSockAddr.sin_family = AF_INET;
	serverSockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverSockAddr.sin_port = htons(PORT);

	if((bind(listenSock, (struct sockaddr *) &serverSockAddr, sizeof(serverSockAddr))) < 0) {
		perror("bind()");
		exit(1);
	}

	if((listen(listenSock, MAX_PENDING)) < 0) {
		perror("listen()");
		exit(1);
	}

	if((epollfd	= epoll_create1(0)) == -1) {
		perror("epoll_create1()");
		exit(1);
	}


	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = listenSock;
	if(epoll_ctl(epollfd, EPOLL_CTL_ADD, listenSock, &ev) == -1) {
		perror("epoll_clt(listenSock)");
		exit(1);
	}

	threadpool thpool = thpool_init(20);

	thpool_add_work(thpool, (void *)check_idle, NULL);
	while(1) {
		if((nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1)) == -1) {
			perror("epoll_wait()");
			exit(1);
		}

		for(n = 0; n < nfds; ++n) {
			if(events[n].data.fd == listenSock) {
				printf("Trying to accept connection...\n");
				if((clientSock = accept4(listenSock, (struct sockaddr *) &serverSockAddr, &clientLen, SOCK_NONBLOCK)) == -1) {
					perror("accept()");
					exit(1);
				}

				if(emptyIdx == MAX_CLIENTS) {
					if(write(clientSock, serverFullMsg, srvFullMsgLen) != srvFullMsgLen) {
						printf("Error writing server full message message!\n");
						close(clientSock);
						continue;
					}
					close(clientSock);
					continue;
				}
				struct epoll_event Event;
				Event.events = EPOLLIN | EPOLLET;
				Event.data.fd = clientSock;
				if(epoll_ctl(epollfd, EPOLL_CTL_ADD, clientSock, &Event) == -1) {
					perror("epoll_ctl(clientSock)");
					exit(1);
				}
				clientConnections[emptyIdx].socket = clientSock;
				clientConnections[emptyIdx].lastPingTime = (int)time(NULL);
				emptyIdx++;
				printf("Accepted connection on descriptor %d\n", clientSock);
			} else {
				int r;
				char buffer[MAX_MSG_SIZE];
				bzero(buffer, MAX_MSG_SIZE);
				// printf("nfds= %d\n", nfds);
				if((r = read(events[n].data.fd, buffer, MAX_MSG_SIZE)) > 0) {
					// broadcastMsg(buffer, r, events[n].data.fd);
					args->msg = buffer;
					args->size = r;
					args->source = events[n].data.fd;
					thpool_add_work(thpool, (void *)handle_message, args);
					// sleep(10);
					// for(i = 0; i < nfds; i++) {
					// 	printf("i = %d\n", i);
					// 	// if(events[n].data.fd != events[i].data.fd && events[i].data.fd != listenSock) {
					// 	if(events[i].data.fd != listenSock) {
					// 		printf("Sending -> %s <- to descriptor %d\n", buffer, events[i].data.fd);
					// 		if(write(events[i].data.fd, buffer, r) != r) {
					// 			printf("Error writing to clientSocket socket\n");
					// 			exit(1);
					// 		}
					// 	}
					// }
				} else if(r == 0) {
					epoll_ctl(epollfd, EPOLL_CTL_DEL, events[n].data.fd, NULL);
					close(events[n].data.fd);
					for(i = 0; i < emptyIdx; i++) {
						if(clientConnections[i].socket == events[n].data.fd) {
							printf("Closing connection on descriptor %d\n", clientConnections[i].socket);
							if(clientConnections[i].authenticated) {
								clientConnections[i].authenticated = false;
								takenUsers[clientConnections[i].usernameHash] = 0;
							}
							memmove(&clientConnections[i], &clientConnections[i+1], emptyIdx-(i+1));
							emptyIdx--;
							break;
						}
					}
				} else {
					break;
				}
				// printf("outside while-read loop\n");
			}
		}
	}

	thpool_destroy(thpool);
	free(events);
	close(listenSock);
	close(epollfd);

	return 0;
}