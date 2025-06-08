#ifndef _NETWORK_H_
#define _NETWORK_H_

#include "request.h"
#include "response.h"
#include "stdint.h"

#define MAX_HOST_LT 50
#define MAX_PT_LT 20
#define MAX_RESOURCE_LT 1024
struct Url{
	char protocol[MAX_PT_LT];
	char host[MAX_HOST_LT];
	char resource[MAX_RESOURCE_LT];
};

int listen_port_80(uint16_t *port);
int read_cli_sock(int cli_sock, struct Request *req);
int write_cli_sock(int cli_sock, struct Response *res);
int wait_for_connections(int sock_fd, int *cli_sock, struct Request *req);
int get(char *URL);
void stop_listening(int sock_fd);

#endif
