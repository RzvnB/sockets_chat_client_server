CC=clang

server: serverEpoll.c thpool.c 
	$(CC) -Wall -o epollServer serverEpoll.c thpool.c -D THPOOL_DEBUG -pthread

client: epollClient.c thpool.c
	$(CC) -Wall -o clientEpoll epollClient.c thpool.c -D THPOOL_DEBUG -pthread
