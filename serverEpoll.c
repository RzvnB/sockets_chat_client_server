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
};



static struct connection_handle clientConnections[MAX_CLIENTS];
// static int clientSockets[MAX_CLIENTS];
static int emptyIdx = 0;

void broadcastMsg(char *msg, int r, int sourceSocket) {
	for(int i = 0; i < emptyIdx; i++) {
		if(clientConnections[i].socket != sourceSocket) {
			// printf("Sending -> %s <- to descriptor %d\n", msg, clientSockets[i]);
				if(write(clientConnections[i].socket, msg, r) != r) {
					printf("Error writing to socket\n");
					exit(1);
				}
		}
	}
}

void handle_message(void *argt) {
	struct message_handle *args = argt;

	printf("Message is %s\n", args->msg);
	if(strcmp(args->msg, "/ping") == 0) {
		// printf("Received ping \n");
		for(int i = 0; i < emptyIdx; i++) {
			if(clientConnections[i].socket == args->source) {
				clientConnections[i].lastPingTime = (int)time(NULL);
			}
		}
	} else {
		broadcastMsg(args->msg, args->size, args->source);
	}
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
					exit(1);
				}
				printf("Closing connection on descriptor %d\n", clientConnections[i].socket);
				close(clientConnections[i].socket);
				memmove(&clientConnections[i], &clientConnections[i+1], emptyIdx-(i+1));
				emptyIdx--;
				break;
			}	
		}
		sleep(5);
	}
}


int main() {
	struct epoll_event ev, events[MAX_EVENTS];

	int listenSock, clientSock, nfds, epollfd;

	int n, i;

	socklen_t clientLen;

	struct message_handle *args = malloc(sizeof(*args));

	if(!args) {
		perror("Failed allocation for message handle");
		exit(1);
	}

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

	threadpool thpool = thpool_init(6);

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